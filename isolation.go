package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ---------- real isolation through ARP spoofing ----------

// activeIsolation holds the state of a device being isolated right now:
// the function that cancels the spoofing and a counter of forged ARP
// packets already sent.
type activeIsolation struct {
	cancel    context.CancelFunc
	packets   int64 // accessed atomically
	since     time.Time
	mac       net.HardwareAddr
	expiresAt time.Time // zero = no deadline, stays isolated until reconnected by hand
}

var isolationsMu sync.Mutex
var isolations = make(map[string]*activeIsolation)

func sendARPReply(handle *pcap.Handle, ethSrc, ethDst net.HardwareAddr, arpSrcMAC net.HardwareAddr, arpSrcIP net.IP, arpDstMAC net.HardwareAddr, arpDstIP net.IP) error {
	eth := layers.Ethernet{SrcMAC: ethSrc, DstMAC: ethDst, EthernetType: layers.EthernetTypeARP}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   arpSrcMAC,
		SourceProtAddress: arpSrcIP.To4(),
		DstHwAddress:      arpDstMAC,
		DstProtAddress:    arpDstIP.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// sendBlockingRA sends a forged Router Advertisement claiming — while
// pretending to be the router's IPv6 address — that it is no longer a
// default route (RouterLifetime=0). Unlike the ARP spoofing, this does not
// intercept the target's IPv6 traffic (which never even reaches the
// laptop, since Wi-Fi delivers unicast directly between stations). The
// goal is only to convince the target's system to drop the IPv6 route and
// fall back to IPv4, which at that point is blocked (ARP spoofing plus
// iptables).
func sendBlockingRA(handle *pcap.Handle, ethSrc, ethDst net.HardwareAddr, gatewayIPv6 net.IP) error {
	eth := layers.Ethernet{SrcMAC: ethSrc, DstMAC: ethDst, EthernetType: layers.EthernetTypeIPv6}
	ip6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255, // RFC 4861 requires hop limit 255 for neighbour discovery packets
		SrcIP:      gatewayIPv6,
		DstIP:      net.ParseIP("ff02::1"), // "all nodes" multicast group
	}
	icmp6 := layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0)}
	if err := icmp6.SetNetworkLayerForChecksum(&ip6); err != nil {
		return err
	}
	ra := layers.ICMPv6RouterAdvertisement{RouterLifetime: 0}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip6, &icmp6, &ra); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

// blockForwarding inserts rules in the iptables/ip6tables FORWARD chain
// that drop any packet to or from this device. It is necessary because on
// machines with Docker (like this one) the kernel runs with
// net.ipv4.ip_forward=1 globally — Docker turns it on to route containers.
// Without these rules the ARP spoofing merely turns the laptop into a
// transparent man-in-the-middle: the kernel forwards the target's traffic
// to the gateway (and back) with no Go code asking it to, and the device
// keeps its internet access.
func blockForwarding(ip string, mac net.HardwareAddr) error {
	if err := exec.Command("iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP").Run(); err != nil {
		return fmt.Errorf("iptables -s %s: %w", ip, err)
	}
	if err := exec.Command("iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP").Run(); err != nil {
		exec.Command("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP").Run()
		return fmt.Errorf("iptables -d %s: %w", ip, err)
	}
	// IPv6 is blocked by MAC as an extra defence beyond the forged RA. The
	// v4 rules use the IP because ARP spoofing guarantees the traffic
	// passes through the laptop; v6 uses the MAC because there is no such
	// guarantee. Best effort: if ip6tables is missing or lacks the mac
	// match, carry on — the forged RA is still the main mitigation.
	_ = exec.Command("ip6tables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac.String(), "-j", "DROP").Run()
	return nil
}

// unblockForwarding removes the rules created by blockForwarding.
func unblockForwarding(ip string, mac net.HardwareAddr) {
	exec.Command("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP").Run()
	exec.Command("ip6tables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac.String(), "-j", "DROP").Run()
}

// cleanOrphanRules finds and removes DROP rules in iptables left over from
// a previous run of Guarita. If the program crashes or is killed (Ctrl+C,
// crash, kill -9) while something is isolated, the ARP spoofing stops
// immediately — it was only a goroutine in memory — but the firewall rule,
// which is only removed when someone clicks "reconnect", keeps blocking the
// device forever, even after the dashboard restarts from scratch and shows
// it as not isolated. Runs once, at startup.
func cleanOrphanRules(network *networkInfo) {
	output, err := exec.Command("iptables", "-L", "FORWARD", "-n").Output()
	if err != nil {
		return
	}

	orphans := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "DROP" {
			continue
		}
		for _, ip := range []string{fields[3], fields[4]} {
			candidate := net.ParseIP(ip)
			if candidate == nil || !network.IPNet.Contains(candidate) {
				continue
			}
			if ip == network.IP.String() || ip == network.Gateway.String() {
				continue
			}
			orphans[ip] = true
		}
	}

	for ip := range orphans {
		for exec.Command("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP").Run() == nil {
			// -D removes a single occurrence per call; repeat until none is left
		}
		for exec.Command("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP").Run() == nil {
		}
		fmt.Printf("Limpei uma regra de bloqueio órfã de %s (sobrou de uma execução anterior do programa)\n", ip)
		recordEvent("limpeza_orfa", ip, "Regra de bloqueio órfã removida do iptables ao iniciar — provavelmente o programa foi encerrado enquanto esse dispositivo estava isolado.")
	}
}

// ipv4BlockActive checks (with "iptables -C", which only tests whether a
// rule exists, changing nothing) that this IP's DROP rules are still in
// place. This is what separates "says it isolated" from "proved it is
// still isolated": a manual `iptables -F`, a firewall restart, or any
// other process touching the rules would go unnoticed, and the dashboard
// would keep showing "isolated" with the block long gone, if it trusted
// only the in-memory map.
func ipv4BlockActive(ip string) bool {
	source := exec.Command("iptables", "-C", "FORWARD", "-s", ip, "-j", "DROP").Run() == nil
	dest := exec.Command("iptables", "-C", "FORWARD", "-d", ip, "-j", "DROP").Run() == nil
	return source && dest
}

// blockedPackets reads the packet counter the kernel already keeps for
// each iptables rule (`-v -x` prints the exact value, with no rounding to
// "K"/"M") and adds up both rules (source and destination) for this IP.
// It is live, numeric proof that the block is not merely decorative: every
// attempt the isolated device makes to reach the network shows up here.
func blockedPackets(ip string) int64 {
	output, err := exec.Command("iptables", "-L", "FORWARD", "-v", "-x", "-n").Output()
	if err != nil {
		return 0
	}
	var total int64
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 || fields[2] != "DROP" {
			continue
		}
		source, dest := fields[7], fields[8]
		if source != ip && dest != ip {
			continue
		}
		if n, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			total += n
		}
	}
	return total
}

// ipv6BlockActive checks whether the ip6tables rule matching on MAC is
// still there.
func ipv6BlockActive(mac net.HardwareAddr) bool {
	return exec.Command("ip6tables", "-C", "FORWARD", "-m", "mac", "--mac-source", mac.String(), "-j", "DROP").Run() == nil
}

// startTrafficCapture takes advantage of the ARP spoofing already making
// the isolated device send its packets to the laptop (thinking it is the
// gateway) to record what it tried to reach before iptables dropped it.
// Without this, "I isolated the device" carries no evidence of what it was
// trying to do. It is free threat intelligence, just by looking at traffic
// that already passes through here anyway.
func startTrafficCapture(handle *pcap.Handle, ip string, targetMAC net.HardwareAddr) {
	if err := handle.SetBPFFilter(fmt.Sprintf("ether src %s", targetMAC.String())); err != nil {
		return // carry on without capture — not critical to the isolation itself
	}

	const destinationLimit = 20
	seen := make(map[string]bool, destinationLimit)
	var seenMu sync.Mutex

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for packet := range source.Packets() {
			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}
			destination := networkLayer.NetworkFlow().Dst().String()

			var description string
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				if dns, ok := dnsLayer.(*layers.DNS); ok && len(dns.Questions) > 0 {
					description = fmt.Sprintf("tentou resolver DNS: %s", dns.Questions[0].Name)
				}
			}
			if description == "" {
				switch {
				case packet.Layer(layers.LayerTypeTCP) != nil:
					tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
					description = fmt.Sprintf("tentou conectar em %s:%s (TCP)", destination, tcp.DstPort)
				case packet.Layer(layers.LayerTypeUDP) != nil:
					udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
					description = fmt.Sprintf("tentou conectar em %s:%s (UDP)", destination, udp.DstPort)
				default:
					continue // neither TCP, UDP nor DNS — ignore
				}
			}

			seenMu.Lock()
			if seen[description] || len(seen) >= destinationLimit {
				seenMu.Unlock()
				continue
			}
			seen[description] = true
			seenMu.Unlock()

			recordEvent("trafego_bloqueado", ip, description)
		}
	}()
}

// isolateDevice starts poisoning the ARP table of both the target device
// and the gateway, making each believe the other is the laptop, and blocks
// forwarding for this IP through iptables. Without that second part the
// kernel (with ip_forward enabled by Docker) would relay the traffic
// anyway and the device would keep its connection.
//
// With duration 0 the device stays isolated indefinitely; otherwise it
// reconnects on its own after that period (see
// startIsolationTimeoutWatcher), which avoids forgetting a device blocked
// forever after a test.
func isolateDevice(network *networkInfo, targetIP net.IP, targetMAC net.HardwareAddr, duration time.Duration) error {
	ip := targetIP.String()
	orderedAt := time.Now()

	isolationsMu.Lock()
	if _, alreadyActive := isolations[ip]; alreadyActive {
		isolationsMu.Unlock()
		return fmt.Errorf("%s já está isolado", ip)
	}
	isolationsMu.Unlock()

	handle, err := pcap.OpenLive(network.Interface, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("não consegui abrir a interface %s pra enviar ARP (rode como root): %w", network.Interface, err)
	}

	if err := blockForwarding(ip, targetMAC); err != nil {
		handle.Close()
		return fmt.Errorf("não consegui bloquear o encaminhamento de %s no iptables (rode como root): %w", ip, err)
	}
	// the containment is only counted as effective once the rule is
	// verified present in the kernel, not when the command returned —
	// same distinction the dashboard makes between "says it isolated" and
	// "proved it is isolated"
	if ipv4BlockActive(ip) {
		recordContainment(ip, orderedAt, time.Now())
	}

	ctx, cancel := context.WithCancel(context.Background())
	state := &activeIsolation{cancel: cancel, since: time.Now(), mac: targetMAC}
	if duration > 0 {
		state.expiresAt = time.Now().Add(duration)
	}

	isolationsMu.Lock()
	isolations[ip] = state
	isolationsMu.Unlock()

	detail := "Isolamento por ARP spoofing iniciado"
	if duration > 0 {
		detail += fmt.Sprintf(" (reconecta sozinho em %s, se ninguém mexer antes)", duration)
	} else {
		detail += " (sem prazo — fica isolado até reconectar manualmente)"
	}
	if network.GatewayIPv6 != nil {
		detail += " — com bloqueio de rota IPv6 via Router Advertisement falso"
	}
	recordEvent("isolado", ip, detail)

	startTrafficCapture(handle, ip, targetMAC)

	go func() {
		defer handle.Close()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			// tell the target: "I am the gateway"
			sendARPReply(handle, network.MAC, targetMAC, network.MAC, network.Gateway, targetMAC, targetIP)
			// tell the gateway: "I am the target" (cuts both directions)
			sendARPReply(handle, network.MAC, network.GatewayMAC, network.MAC, targetIP, network.GatewayMAC, network.Gateway)
			atomic.AddInt64(&state.packets, 2)
			// drop the target's default IPv6 route, forcing a fallback to IPv4 (already blocked)
			if network.GatewayIPv6 != nil {
				sendBlockingRA(handle, network.MAC, targetMAC, network.GatewayIPv6)
			}

			select {
			case <-ctx.Done():
				restoreARP(handle, network, targetIP, targetMAC)
				return
			case <-ticker.C:
			}
		}
	}()

	return nil
}

// restoreARP tells the target and the gateway the true IP->MAC mapping, so
// the network goes back to normal without waiting for the ARP tables to
// expire on their own.
func restoreARP(handle *pcap.Handle, network *networkInfo, targetIP net.IP, targetMAC net.HardwareAddr) {
	for i := 0; i < 4; i++ {
		sendARPReply(handle, network.GatewayMAC, targetMAC, network.GatewayMAC, network.Gateway, targetMAC, targetIP)
		sendARPReply(handle, targetMAC, network.GatewayMAC, targetMAC, targetIP, network.GatewayMAC, network.Gateway)
		time.Sleep(300 * time.Millisecond)
	}
}

func reconnectDevice(ip string, network *networkInfo) error {
	isolationsMu.Lock()
	state, ok := isolations[ip]
	if ok {
		delete(isolations, ip)
	}
	isolationsMu.Unlock()

	if !ok {
		return fmt.Errorf("%s não está isolado", ip)
	}
	state.cancel()
	unblockForwarding(ip, state.mac)
	recordEvent("reconectado", ip, "Isolamento cancelado, dispositivo reconectado à rede principal")
	return nil
}

// startIsolationTimeoutWatcher periodically checks whether any isolation
// with a deadline has expired, and reconnects it on its own. It runs in
// the background from the moment the program starts, not only while
// someone has the dashboard open.
func startIsolationTimeoutWatcher(network *networkInfo) {
	go func() {
		for {
			time.Sleep(30 * time.Second)

			isolationsMu.Lock()
			var expired []string
			now := time.Now()
			for ip, state := range isolations {
				if !state.expiresAt.IsZero() && now.After(state.expiresAt) {
					expired = append(expired, ip)
				}
			}
			isolationsMu.Unlock()

			for _, ip := range expired {
				if err := reconnectDevice(ip, network); err == nil {
					recordEvent("timeout_isolamento", ip, "O prazo de isolamento definido na hora de isolar venceu — dispositivo reconectado automaticamente.")
				}
			}
		}
	}()
}
