package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// ---------- discovery of the real network (Wi-Fi/LAN) ----------

type networkInfo struct {
	Interface     string
	IP            net.IP
	IPNet         *net.IPNet
	MAC           net.HardwareAddr
	Gateway       net.IP
	GatewayMAC    net.HardwareAddr
	GatewayIPv6   net.IP       // router's IPv6 link-local address, nil when the network has no IPv6
	ExtraNetworks []*net.IPNet // neighbouring subnets the user asked to scan (REDES_EXTRAS)
}

// parseExtraNetworks reads the REDES_EXTRAS variable, a comma-separated
// list of CIDRs (e.g. "192.168.1.0/24,192.168.3.0/24").
//
// The default scan covers only the interface's own subnet, because that is
// the only place where the rest of the program works: ARP is a link-layer
// protocol and does not cross a router, so from another subnet there is no
// way to learn a MAC, a vendor, or to contain anything. Devices found here
// show up in the dashboard as observable but with no containment action
// available — see OutsideSubnet in deviceResult.
//
// This is opt-in on purpose: scanning a range that may not be yours is not
// something the program should decide to do on its own.
func parseExtraNetworks(value string) []*net.IPNet {
	var networks []*net.IPNet
	for _, piece := range strings.Split(value, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		_, network, err := net.ParseCIDR(piece)
		if err != nil {
			fmt.Printf("REDES_EXTRAS: ignorando %q (%v)\n", piece, err)
			continue
		}
		if size, _ := network.Mask.Size(); size < 22 {
			fmt.Printf("REDES_EXTRAS: ignorando %s — faixa grande demais pra varrer (use /22 ou menor)\n", network)
			continue
		}
		networks = append(networks, network)
	}
	return networks
}

// hostsToScan joins the addresses of the local subnet with those of any
// configured extra ranges.
func hostsToScan(network *networkInfo) []string {
	hosts := subnetHosts(network.IPNet)
	for _, extra := range network.ExtraNetworks {
		hosts = append(hosts, subnetHosts(extra)...)
	}
	return hosts
}

// detectNetwork finds which interface holds the default route (the real
// network the laptop is using, Wi-Fi or wired) and returns its IP, mask,
// MAC and gateway.
func detectNetwork() (*networkInfo, error) {
	output, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("não foi possível ler a rota padrão: %w", err)
	}
	fields := strings.Fields(string(output))
	var gatewayStr, iface string
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			gatewayStr = fields[i+1]
		}
		if field == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
	}
	if iface == "" || gatewayStr == "" {
		return nil, fmt.Errorf("não encontrei a interface/gateway padrão (saída: %q)", output)
	}

	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	addresses, err := ni.Addrs()
	if err != nil {
		return nil, err
	}
	var ipNet *net.IPNet
	for _, addr := range addresses {
		if ipn, ok := addr.(*net.IPNet); ok && ipn.IP.To4() != nil {
			ipNet = ipn
			break
		}
	}
	if ipNet == nil {
		return nil, fmt.Errorf("interface %s não tem IPv4", iface)
	}

	network := &networkInfo{
		Interface: iface,
		IP:        ipNet.IP.To4(),
		IPNet:     &net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask).To4(), Mask: ipNet.Mask},
		MAC:       ni.HardwareAddr,
		Gateway:   net.ParseIP(gatewayStr).To4(),
	}

	// make sure the gateway is in the ARP table, and learn its MAC
	_ = exec.Command("ping", "-c", "1", "-W", "1", gatewayStr).Run()
	if mac, ok := readARPTable(iface)[network.Gateway.String()]; ok {
		network.GatewayMAC = mac
	} else {
		return nil, fmt.Errorf("não consegui descobrir o MAC do gateway %s", gatewayStr)
	}

	network.GatewayIPv6 = discoverIPv6Gateway(iface)

	return network, nil
}

// discoverIPv6Gateway reads the default IPv6 route (usually the router's
// link-local address, announced through a Router Advertisement). When the
// network has no IPv6 configured it returns nil, and in that case the
// isolation does not need to worry about IPv6 at all.
func discoverIPv6Gateway(iface string) net.IP {
	output, err := exec.Command("ip", "-6", "route", "show", "default", "dev", iface).Output()
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(output))
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1])
		}
	}
	return nil
}

// subnetHosts enumerates every host address of the given subnet, leaving
// out the network and broadcast addresses.
func subnetHosts(ipNet *net.IPNet) []string {
	var hosts []string
	base := ipNet.IP.Mask(ipNet.Mask)
	for ip := cloneIP(base); ipNet.Contains(ip); incrementIP(ip) {
		if !ip.Equal(base) {
			hosts = append(hosts, ip.String())
		}
	}
	// drop the broadcast address (last one in the range), if present
	if len(hosts) > 0 {
		last := net.ParseIP(hosts[len(hosts)-1]).To4()
		if last.Equal(broadcastOf(ipNet)) {
			hosts = hosts[:len(hosts)-1]
		}
	}
	return hosts
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcastOf(ipNet *net.IPNet) net.IP {
	ip := cloneIP(ipNet.IP.Mask(ipNet.Mask).To4())
	mask := ipNet.Mask
	for i := range ip {
		ip[i] |= ^mask[i]
	}
	return ip
}

// readARPTable reads /proc/net/arp and returns the IP -> MAC map of the
// addresses already resolved ("complete" entries) on the given interface.
func readARPTable(iface string) map[string]net.HardwareAddr {
	table := make(map[string]net.HardwareAddr)
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return table
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // skip the header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		ip, flags, macStr, dev := fields[0], fields[2], fields[3], fields[5]
		if dev != iface || flags != "0x2" { // 0x2 = complete entry (ATF_COM)
			continue
		}
		if mac, err := net.ParseMAC(macStr); err == nil {
			table[ip] = mac
		}
	}
	return table
}
