package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ---------- security of our own Wi-Fi ----------

// Everything built so far looks at the devices inside the LAN, but the
// Wi-Fi radio itself is another attack surface: a fake network imitating
// yours (an evil twin) or weak encryption on your own router would never
// show up in any host scan. We use nmcli — shipped with NetworkManager,
// the default on most desktop distributions — to see that.
type visibleWifiNetwork struct {
	active, ssid, bssid, security string
}

// listWifiNetworks reads `nmcli -t -f active,ssid,bssid,security dev
// wifi`. In terse mode (-t) nmcli separates fields with ":", but the BSSID
// itself also uses ":" — nmcli escapes those as "\:", so we protect that
// sequence before splitting the fields and undo it afterwards.
func listWifiNetworks() []visibleWifiNetwork {
	exec.Command("nmcli", "dev", "wifi", "rescan").Run() // best effort, error ignored
	time.Sleep(2 * time.Second)

	output, err := exec.Command("nmcli", "-t", "-f", "active,ssid,bssid,security", "dev", "wifi").Output()
	if err != nil {
		return nil
	}

	var networks []visibleWifiNetwork
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		protected := strings.ReplaceAll(line, `\:`, "\x00")
		fields := strings.SplitN(protected, ":", 4)
		if len(fields) < 4 {
			continue
		}
		unescape := func(s string) string { return strings.ReplaceAll(s, "\x00", ":") }
		networks = append(networks, visibleWifiNetwork{
			active:   unescape(fields[0]),
			ssid:     unescape(fields[1]),
			bssid:    unescape(fields[2]),
			security: unescape(fields[3]),
		})
	}
	return networks
}

// rateWifiSecurity classifies the security string nmcli returns (e.g.
// "WPA1 WPA2", "WEP", or "--" for an open network).
func rateWifiSecurity(security string) (risk, reason string) {
	switch {
	case security == "" || security == "--":
		return "alto", "Rede Wi-Fi sem senha (aberta) — qualquer um por perto pode entrar e ver seu tráfego."
	case strings.Contains(security, "WEP"):
		return "alto", "Rede Wi-Fi protegida por WEP, um protocolo quebrado há mais de 15 anos — pode ser invadida em minutos."
	case strings.Contains(security, "WPA3"):
		return "baixo", "Rede Wi-Fi protegida por WPA3, o padrão mais atual."
	case strings.Contains(security, "WPA2"):
		return "baixo", "Rede Wi-Fi protegida por WPA2 — adequado pro uso doméstico."
	case strings.Contains(security, "WPA"):
		return "médio", "Rede Wi-Fi protegida só por WPA1, considerado fraco hoje em dia — o ideal é migrar pra WPA2 ou WPA3 nas configurações do roteador."
	default:
		return "", fmt.Sprintf("Tipo de segurança do Wi-Fi não reconhecido pelo programa (%s).", security)
	}
}

var wifiSecurityMu sync.RWMutex
var currentWifiSecurity struct {
	SSID, Protocol, Risk, Reason string
	LastCheck                    time.Time
}

func checkWifiSecurity(networks []visibleWifiNetwork) {
	for _, r := range networks {
		if r.active != "sim" {
			continue
		}
		risk, reason := rateWifiSecurity(r.security)
		wifiSecurityMu.Lock()
		currentWifiSecurity.SSID = r.ssid
		currentWifiSecurity.Protocol = r.security
		currentWifiSecurity.Risk = risk
		currentWifiSecurity.Reason = reason
		currentWifiSecurity.LastCheck = time.Now()
		wifiSecurityMu.Unlock()
		return
	}
}

func readWifiCache() (ssid, protocol, risk, reason string, lastCheck time.Time) {
	wifiSecurityMu.RLock()
	defer wifiSecurityMu.RUnlock()
	i := currentWifiSecurity
	return i.SSID, i.Protocol, i.Risk, i.Reason, i.LastCheck
}

// evilTwinMu/alertedEvilTwins avoid re-alerting on every cycle for the
// same impostor BSSID — only the first time it shows up.
var evilTwinMu sync.Mutex
var alertedEvilTwins = make(map[string]bool)

// checkEvilTwin looks, among the visible networks, for one with the SAME
// name (SSID) as the network the laptop is using but OPEN (no password)
// while the real one is protected. Dual-band home routers normally
// advertise the same SSID with different BSSIDs and the SAME security —
// which is why we do not alert on "same SSID, different BSSID" alone, that
// is far too common and would produce false positives all the time. A
// passwordless copy of your protected network is a much more specific sign
// of an evil twin attack.
func checkEvilTwin(networks []visibleWifiNetwork) {
	var current *visibleWifiNetwork
	for i := range networks {
		if networks[i].active == "sim" {
			current = &networks[i]
			break
		}
	}
	if current == nil || current.ssid == "" {
		return // not on Wi-Fi (a wired network, say) — nothing to check
	}
	protected := current.security != "" && current.security != "--"
	if !protected {
		return
	}

	for _, r := range networks {
		if r.bssid == current.bssid || r.ssid != current.ssid {
			continue
		}
		if r.security != "" && r.security != "--" {
			continue // also protected, most likely just the other band of the same router
		}

		evilTwinMu.Lock()
		alreadyAlerted := alertedEvilTwins[r.bssid]
		alertedEvilTwins[r.bssid] = true
		evilTwinMu.Unlock()
		if alreadyAlerted {
			continue
		}

		recordEvent("alerta_evil_twin", r.bssid, fmt.Sprintf(
			"Um ponto de acesso SEM SENHA está anunciando o mesmo nome (%q) da sua rede Wi-Fi, que normalmente é protegida por %s — pode ser um ataque de rede falsa (evil twin) tentando roubar sua conexão.",
			current.ssid, current.security))
	}
}

// startWifiCheck runs in the background, reusing the same list of visible
// networks for both checks (which avoids sending two separate rescans per
// cycle).
func startWifiCheck() {
	go func() {
		for {
			networks := listWifiNetworks()
			checkWifiSecurity(networks)
			checkEvilTwin(networks)
			time.Sleep(2 * time.Minute)
		}
	}()
}
