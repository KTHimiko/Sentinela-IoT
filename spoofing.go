package main

import (
	"fmt"
	"net"
	"sync"
)

// ---------- detection of ARP spoofing by third parties ----------

// arpSpoofMu guards suspectGatewayMAC: the last "wrong" MAC seen in the
// gateway's place, so the alert fires on the transition (when the MAC
// changes) instead of on every scan cycle while the attack goes on.
var arpSpoofMu sync.Mutex
var suspectGatewayMAC string

// checkGatewaySpoofing compares the MAC that the laptop's own ARP table
// shows for the gateway IP against the real one (learned once at startup,
// in detectNetwork). The program also performs ARP spoofing, to isolate
// devices, but that never rewrites the gateway entry in the laptop's own
// ARP table — only the isolated target's and the router's — so a change
// here means ANOTHER device on the network is running a genuine ARP
// spoofing attack (a visitor's laptop running Ettercap/Bettercap, say).
func checkGatewaySpoofing(network *networkInfo, arpTable map[string]net.HardwareAddr) {
	currentMAC, ok := arpTable[network.Gateway.String()]
	if !ok {
		return
	}
	current := currentMAC.String()
	expected := network.GatewayMAC.String()

	arpSpoofMu.Lock()
	defer arpSpoofMu.Unlock()

	if current == expected {
		if suspectGatewayMAC != "" {
			recordEvent("arp_spoofing_resolvido", network.Gateway.String(),
				fmt.Sprintf("O MAC do gateway voltou ao valor esperado (%s).", expected))
			suspectGatewayMAC = ""
		}
		return
	}

	if current != suspectGatewayMAC {
		recordEvent("alerta_arp_spoofing", network.Gateway.String(),
			fmt.Sprintf("O MAC do gateway (%s) mudou pra %s — pode ser outro dispositivo na rede fazendo ARP spoofing (ataque man-in-the-middle)!", expected, current))
		suspectGatewayMAC = current
	}
}

// arpDupMu guards the set of MACs already reported as duplicated, so the
// alert fires on the transition (when the pattern shows up) and not on
// every scan while it persists.
var arpDupMu sync.Mutex
var reportedDuplicateMACs = make(map[string]bool)

// detectDuplicateMAC looks in the laptop's own ARP table for a MAC
// answering for two or more IPs at the same time. A legitimate device has
// one MAC per interface, so this pattern is the classic signature of ARP
// poisoning: the attacker announces itself as several hosts at once to
// intercept their traffic. The gateway is skipped because spoofing
// against it is already covered by checkGatewaySpoofing, and so is the
// laptop's own MAC, since it is the one doing the isolation spoofing.
func detectDuplicateMAC(network *networkInfo, arpTable map[string]net.HardwareAddr) {
	ipsByMAC := make(map[string][]string)
	ourMAC := ""
	if network.MAC != nil {
		ourMAC = network.MAC.String()
	}
	gatewayMAC := network.GatewayMAC.String()
	for ip, mac := range arpTable {
		m := mac.String()
		if m == ourMAC || m == gatewayMAC || ip == network.Gateway.String() {
			continue
		}
		ipsByMAC[m] = append(ipsByMAC[m], ip)
	}

	for mac, ips := range ipsByMAC {
		arpDupMu.Lock()
		alreadyReported := reportedDuplicateMACs[mac]
		if len(ips) >= 2 {
			if !alreadyReported {
				reportedDuplicateMACs[mac] = true
				arpDupMu.Unlock()
				recordEvent("alerta_arp_duplicado", ips[0], fmt.Sprintf(
					"O mesmo MAC (%s) está respondendo por %d IPs ao mesmo tempo (%v) — um dispositivo legítimo tem um MAC por interface, então isso é sinal de ARP poisoning tentando interceptar o tráfego desses hosts.", mac, len(ips), ips))
				continue
			}
		} else if alreadyReported {
			delete(reportedDuplicateMACs, mac)
		}
		arpDupMu.Unlock()
	}
}
