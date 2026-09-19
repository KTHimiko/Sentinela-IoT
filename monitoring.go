package main

import (
	"fmt"
	"sync"
	"time"
)

// ---------- continuous monitoring ----------

// stateMu guards the result of the last scan, which is cached and served
// to whoever opens the dashboard — instead of scanning the network from
// scratch on every page load, which is slow and is not how a real NOC
// works (it observes continuously, not on demand).
var stateMu sync.RWMutex
var lastResults []deviceResult
var lastUpdate time.Time

func refreshCache(network *networkInfo) []deviceResult {
	start := time.Now()
	current := scanNetwork(network)
	recordScanDuration(time.Since(start))
	noteRiskLevel(current)

	stateMu.Lock()
	lastResults = current
	lastUpdate = time.Now()
	stateMu.Unlock()
	return current
}

func readCache() ([]deviceResult, time.Time) {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return lastResults, lastUpdate
}

func byIP(rs []deviceResult) map[string]deviceResult {
	m := make(map[string]deviceResult, len(rs))
	for _, r := range rs {
		m[r.IP] = r
	}
	return m
}

// evasionCandidates records, per vendor, when a device that was isolated
// left the network — so it can be compared against new devices that show
// up right afterwards (see detectChanges).
var evasionMu sync.Mutex
var evasionCandidates = make(map[string]time.Time)

const evasionWindow = 3 * time.Minute

// detectChanges compares the previous scan with the current one and
// records what changed in the history: a new device, one that vanished,
// or a risk that moved. Isolation and reconnection are recorded where
// they happen (isolateDevice/reconnectDevice), not here.
func detectChanges(previous map[string]deviceResult, current []deviceResult) {
	// a sharp drop in the number of active devices is more likely a
	// Wi-Fi/router problem than many devices powering off at the same
	// time, so it deserves its own alert on top of the individual
	// "dispositivo_saiu" events recorded below
	countBefore, countAfter := len(previous), len(current)
	if countBefore >= 4 && countAfter <= countBefore/2 {
		recordEvent("alerta_saude_rede", "", fmt.Sprintf(
			"O número de dispositivos ativos caiu de %d pra %d nessa varredura — verifique o Wi-Fi/roteador antes de assumir que são vários aparelhos desligados.", countBefore, countAfter))
	}

	seen := make(map[string]bool, len(current))
	for _, r := range current {
		seen[r.IP] = true
		old, existed := previous[r.IP]
		if !existed {
			deviceType := r.ProbableType
			if deviceType == "" {
				deviceType = "tipo não identificado"
			}
			// a new device from the same vendor as one that left while
			// isolated a short while ago is suspicious: it may be the same
			// device dodging the block by changing MAC/IP (modern phones
			// generate a random MAC per Wi-Fi network)
			if r.Vendor != "" && r.Vendor != "Desconhecido" {
				evasionMu.Lock()
				when, suspect := evasionCandidates[r.Vendor]
				evasionMu.Unlock()
				if suspect && time.Since(when) < evasionWindow {
					recordEvent("alerta_evasao", r.IP, fmt.Sprintf(
						"Dispositivo novo do mesmo fabricante (%s) apareceu pouco depois de um dispositivo isolado sair da rede — pode ser o mesmo aparelho evitando o bloqueio ao trocar de MAC/IP.", r.Vendor))
				}
			}
			// the persistent inventory tells a genuinely new device (a MAC
			// never seen) from an old acquaintance that merely left and
			// came back, cutting the repeated "new device" noise for the
			// same hardware that was observed in the history
			if alreadyKnown(r.MAC) {
				recordEvent("dispositivo_voltou", r.IP, fmt.Sprintf("Reapareceu na rede (%s)", deviceType))
			} else {
				recordEvent("novo_dispositivo", r.IP, fmt.Sprintf("Apareceu na rede pela primeira vez (%s)", deviceType))
			}
			continue
		}
		if old.Risk != r.Risk && !r.Trusted {
			recordEvent("mudanca_risco", r.IP, fmt.Sprintf("Risco mudou de %s pra %s", old.Risk, r.Risk))
		}
		// if the device still counts as isolated but the firewall rule that
		// confirmed it is gone, that is a serious containment failure
		// (iptables flushed by hand, firewall service restarted, and so on)
		// — alert once, on the transition
		if r.Isolated && old.Isolated && old.IPv4BlockActive && !r.IPv4BlockActive {
			recordEvent("alerta_bloqueio", r.IP, "O bloqueio IPv4 no iptables não está mais ativo, mas o dispositivo ainda consta como isolado — verifique manualmente!")
		}
		// the same IP answering with a different MAC, without the old
		// device ever leaving the network (that would have produced a
		// "dispositivo_saiu" first) — points to an IP conflict or an ARP
		// spoofing attack aimed at this specific device rather than at the
		// gateway, which checkGatewaySpoofing already covers
		if old.MAC != "" && r.MAC != "" && old.MAC != r.MAC {
			recordEvent("alerta_conflito_ip", r.IP, fmt.Sprintf(
				"O MAC que responde por esse IP mudou de %s pra %s sem o dispositivo antigo sair da rede — pode ser conflito de IP ou ARP spoofing mirando esse dispositivo.", old.MAC, r.MAC))
		}
		// a port that was not open in the previous scan and shows up now —
		// more specific and more actionable than just "risk changed"
		wasOpen := make(map[string]bool, len(old.PortNumbers))
		for _, p := range old.PortNumbers {
			wasOpen[p] = true
		}
		for _, p := range r.PortNumbers {
			if !wasOpen[p] {
				recordEvent("porta_nova", r.IP, fmt.Sprintf("A porta %s abriu nesse dispositivo (não estava aberta na varredura anterior)", p))
			}
		}
	}
	for ip, r := range previous {
		if seen[ip] {
			continue
		}
		recordEvent("dispositivo_saiu", ip, "Não respondeu mais na varredura (pode estar desligado ou ter saído da rede)")
		if r.Isolated && r.Vendor != "" && r.Vendor != "Desconhecido" {
			evasionMu.Lock()
			evasionCandidates[r.Vendor] = time.Now()
			evasionMu.Unlock()
		}
	}

	// record in the persistent inventory everything that answered in this
	// scan — done only after the comparisons above, so a device is not
	// marked as known before deciding whether it is new. One single write
	// per scan, not one per device.
	for _, r := range current {
		markSeen(r.MAC, r.IP)
	}
	saveKnownDevices()
}

// startContinuousMonitoring runs the scan in the background on a fixed
// interval, without depending on anyone opening the dashboard. This loop
// is what turns the project from an on-demand scanner into a NOC.
func startContinuousMonitoring(network *networkInfo, interval time.Duration) {
	go func() {
		firstScan := true
		var previous map[string]deviceResult
		for {
			current := refreshCache(network)
			if !firstScan {
				detectChanges(previous, current)
			}
			firstScan = false
			previous = byIP(current)
			time.Sleep(interval)
		}
	}()
}
