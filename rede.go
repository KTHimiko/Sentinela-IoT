package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

// ---------- detecção da rede real (Wi-Fi/LAN) ----------

type infoRede struct {
	Interface   string
	IP          net.IP
	IPNet       *net.IPNet
	MAC         net.HardwareAddr
	Gateway     net.IP
	GatewayMAC  net.HardwareAddr
	GatewayIPv6 net.IP       // endereço link-local IPv6 do roteador, se a rede tiver IPv6 (nil se não tiver)
	RedesExtras []*net.IPNet // sub-redes vizinhas que o usuário pediu pra varrer (REDES_EXTRAS)
}

// lerRedesExtras interpreta a variável REDES_EXTRAS, uma lista de CIDRs
// separados por vírgula (ex: "192.168.1.0/24,192.168.3.0/24").
//
// A varredura padrão cobre só a sub-rede da própria interface, porque é
// só nela que o resto do programa funciona: ARP é um protocolo de enlace
// e não atravessa roteador, então de outra sub-rede não dá pra descobrir
// MAC, nem fabricante, nem isolar nada. Dispositivos encontrados aqui
// aparecem no painel como observáveis, mas sem ação de contenção
// disponível — ver ForaDaSubRede em resultadoDispositivo.
//
// É opt-in de propósito: varrer faixa que não é sua não é algo que o
// programa deva fazer sozinho.
func lerRedesExtras(valor string) []*net.IPNet {
	var redes []*net.IPNet
	for _, pedaco := range strings.Split(valor, ",") {
		pedaco = strings.TrimSpace(pedaco)
		if pedaco == "" {
			continue
		}
		_, rede, err := net.ParseCIDR(pedaco)
		if err != nil {
			fmt.Printf("REDES_EXTRAS: ignorando %q (%v)\n", pedaco, err)
			continue
		}
		if tam, _ := rede.Mask.Size(); tam < 22 {
			fmt.Printf("REDES_EXTRAS: ignorando %s — faixa grande demais pra varrer (use /22 ou menor)\n", rede)
			continue
		}
		redes = append(redes, rede)
	}
	return redes
}

// hostsParaVarrer junta os endereços da sub-rede local com os das faixas
// extras configuradas.
func hostsParaVarrer(rede *infoRede) []string {
	hosts := hostsDaSubRede(rede.IPNet)
	for _, extra := range rede.RedesExtras {
		hosts = append(hosts, hostsDaSubRede(extra)...)
	}
	return hosts
}

// detectarRede descobre qual interface tem a rota padrão (a rede real
// que o notebook está usando: Wi-Fi ou cabo) e devolve IP, máscara,
// MAC e o gateway dessa rede.
func detectarRede() (*infoRede, error) {
	saida, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, fmt.Errorf("não foi possível ler a rota padrão: %w", err)
	}
	campos := strings.Fields(string(saida))
	var gatewayStr, iface string
	for i, campo := range campos {
		if campo == "via" && i+1 < len(campos) {
			gatewayStr = campos[i+1]
		}
		if campo == "dev" && i+1 < len(campos) {
			iface = campos[i+1]
		}
	}
	if iface == "" || gatewayStr == "" {
		return nil, fmt.Errorf("não encontrei a interface/gateway padrão (saída: %q)", saida)
	}

	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", iface, err)
	}
	enderecos, err := ni.Addrs()
	if err != nil {
		return nil, err
	}
	var ipNet *net.IPNet
	for _, end := range enderecos {
		if ipn, ok := end.(*net.IPNet); ok && ipn.IP.To4() != nil {
			ipNet = ipn
			break
		}
	}
	if ipNet == nil {
		return nil, fmt.Errorf("interface %s não tem IPv4", iface)
	}

	rede := &infoRede{
		Interface: iface,
		IP:        ipNet.IP.To4(),
		IPNet:     &net.IPNet{IP: ipNet.IP.Mask(ipNet.Mask).To4(), Mask: ipNet.Mask},
		MAC:       ni.HardwareAddr,
		Gateway:   net.ParseIP(gatewayStr).To4(),
	}

	// garante que o gateway esteja na tabela ARP e descobre o MAC dele
	_ = exec.Command("ping", "-c", "1", "-W", "1", gatewayStr).Run()
	if mac, ok := lerTabelaARP(iface)[rede.Gateway.String()]; ok {
		rede.GatewayMAC = mac
	} else {
		return nil, fmt.Errorf("não consegui descobrir o MAC do gateway %s", gatewayStr)
	}

	rede.GatewayIPv6 = descobrirGatewayIPv6(iface)

	return rede, nil
}

// descobrirGatewayIPv6 lê a rota padrão IPv6 (normalmente o link-local
// do roteador, anunciado via Router Advertisement). Se a rede não tiver
// IPv6 configurado, devolve nil — nesse caso o isolamento nem precisa
// se preocupar com IPv6.
func descobrirGatewayIPv6(iface string) net.IP {
	saida, err := exec.Command("ip", "-6", "route", "show", "default", "dev", iface).Output()
	if err != nil {
		return nil
	}
	campos := strings.Fields(string(saida))
	for i, campo := range campos {
		if campo == "via" && i+1 < len(campos) {
			return net.ParseIP(campos[i+1])
		}
	}
	return nil
}

// hostsDaSubRede enumera todos os IPs "de host" (exclui rede e broadcast)
// da sub-rede detectada.
func hostsDaSubRede(ipNet *net.IPNet) []string {
	var hosts []string
	base := ipNet.IP.Mask(ipNet.Mask)
	for ip := cloneIP(base); ipNet.Contains(ip); incrementaIP(ip) {
		if !ip.Equal(base) {
			hosts = append(hosts, ip.String())
		}
	}
	// remove o endereço de broadcast (último IP da faixa), se existir
	if len(hosts) > 0 {
		ultimo := net.ParseIP(hosts[len(hosts)-1]).To4()
		bcast := broadcastDe(ipNet)
		if ultimo.Equal(bcast) {
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

func incrementaIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func broadcastDe(ipNet *net.IPNet) net.IP {
	ip := cloneIP(ipNet.IP.Mask(ipNet.Mask).To4())
	mask := ipNet.Mask
	for i := range ip {
		ip[i] |= ^mask[i]
	}
	return ip
}

// lerTabelaARP lê /proc/net/arp e devolve o mapa IP -> MAC dos
// endereços já resolvidos (entradas "completas") na interface dada.
func lerTabelaARP(iface string) map[string]net.HardwareAddr {
	mapa := make(map[string]net.HardwareAddr)
	arquivo, err := os.Open("/proc/net/arp")
	if err != nil {
		return mapa
	}
	defer arquivo.Close()

	scanner := bufio.NewScanner(arquivo)
	scanner.Scan() // pula cabeçalho
	for scanner.Scan() {
		campos := strings.Fields(scanner.Text())
		if len(campos) < 6 {
			continue
		}
		ip, flags, macStr, dev := campos[0], campos[2], campos[3], campos[5]
		if dev != iface || flags != "0x2" { // 0x2 = entrada completa (ATF_COM)
			continue
		}
		if mac, err := net.ParseMAC(macStr); err == nil {
			mapa[ip] = mac
		}
	}
	return mapa
}
