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

// ---------- isolamento real via ARP spoofing ----------

// isolamentoAtivo guarda o estado de um dispositivo que está sendo
// isolado agora: a função pra cancelar o spoofing e um contador de
// pacotes ARP forjados já enviados.
type isolamentoAtivo struct {
	cancelar context.CancelFunc
	pacotes  int64 // acessado via atomic
	desde    time.Time
	mac      net.HardwareAddr
	expiraEm time.Time // zero = sem prazo, fica isolado até reconectar manualmente
}

var isolamentosMu sync.Mutex
var isolamentos = make(map[string]*isolamentoAtivo)

func enviarARPReply(handle *pcap.Handle, ethSrc, ethDst net.HardwareAddr, arpSrcMAC net.HardwareAddr, arpSrcIP net.IP, arpDstMAC net.HardwareAddr, arpDstIP net.IP) error {
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

// enviarRABloqueio manda um Router Advertisement falso, dizendo que o
// roteador (fingindo ser o endereço IPv6 dele) não serve mais como
// rota padrão (RouterLifetime=0). Diferente do ARP spoofing, isso não
// intercepta o tráfego IPv6 do alvo (que nem passa pelo notebook, já
// que Wi-Fi entrega unicast direto entre as estações) — o objetivo é
// só convencer o sistema do alvo a abandonar a rota IPv6 e cair pra
// IPv4, que aí sim está bloqueado (ARP spoofing + iptables).
func enviarRABloqueio(handle *pcap.Handle, ethSrc, ethDst net.HardwareAddr, gatewayIPv6 net.IP) error {
	eth := layers.Ethernet{SrcMAC: ethSrc, DstMAC: ethDst, EthernetType: layers.EthernetTypeIPv6}
	ip6 := layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255, // RFC 4861 exige hop limit 255 pra pacotes de descoberta de vizinhança
		SrcIP:      gatewayIPv6,
		DstIP:      net.ParseIP("ff02::1"), // grupo multicast "todos os nós"
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

// bloquearEncaminhamento insere regras no FORWARD do iptables/ip6tables
// que derrubam qualquer pacote de/pra esse dispositivo. É necessário
// porque em máquinas com Docker (como esta) o kernel roda com
// net.ipv4.ip_forward=1 global — o Docker liga isso pra rotear os
// containers. Sem essas regras, o ARP spoofing só faz o notebook virar
// um "man-in-the-middle" transparente: o kernel encaminha o tráfego do
// alvo pro gateway (e vice-versa) mesmo sem nenhum código Go pedindo
// isso, e o dispositivo continua com internet normalmente.
func bloquearEncaminhamento(ip string, mac net.HardwareAddr) error {
	if err := exec.Command("iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP").Run(); err != nil {
		return fmt.Errorf("iptables -s %s: %w", ip, err)
	}
	if err := exec.Command("iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP").Run(); err != nil {
		exec.Command("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP").Run()
		return fmt.Errorf("iptables -d %s: %w", ip, err)
	}
	// IPv6: bloqueia por MAC (defesa extra além do RA falso — o tráfego
	// v4 usa IP porque o ARP spoofing garante que passa pelo notebook;
	// o v6 usa MAC porque não há garantia de que vai passar por aqui).
	// Best-effort: se ip6tables não existir/não tiver a extensão mac,
	// segue o baile — o RA falso continua sendo a mitigação principal.
	_ = exec.Command("ip6tables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac.String(), "-j", "DROP").Run()
	return nil
}

// liberarEncaminhamento remove as regras criadas por bloquearEncaminhamento.
func liberarEncaminhamento(ip string, mac net.HardwareAddr) {
	exec.Command("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP").Run()
	exec.Command("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP").Run()
	exec.Command("ip6tables", "-D", "FORWARD", "-m", "mac", "--mac-source", mac.String(), "-j", "DROP").Run()
}

// portaPortalCativo/portaPortalCativoTLS são onde os servidores HTTP e
// HTTPS do portal cativo escutam (iniciarPortalCativo, em portal.go) —
// separadas da porta do dashboard.
const portaPortalCativo = "8091"
const portaPortalCativoTLS = "8092"

// ativarPortalCativo redireciona (via DNAT) o tráfego HTTP **e**
// HTTPS do dispositivo isolado pro portal cativo local, em vez de
// simplesmente derrubar tudo. Como o destino vira o próprio notebook,
// esse tráfego nem passa pelo FORWARD (vira entrega local, INPUT),
// então não é pego pelas regras de DROP que bloqueiam o resto — dá pro
// dispositivo isolado ver exatamente uma página, e nada mais.
//
// A porta 443 também precisa ser redirecionada porque a maioria dos
// sites/apps hoje conecta direto em HTTPS — só a porta 80 deixaria o
// navegador falhar em silêncio na maioria das tentativas. O portal
// nessa porta usa um certificado autoassinado (gerarCertificadoAutoAssinado
// em portal.go), então o navegador mostra aviso de certificado — é uma
// limitação conhecida de qualquer portal cativo em HTTPS, não só do
// nosso.
func ativarPortalCativo(ip string, rede *infoRede) error {
	destinoHTTP := net.JoinHostPort(rede.IP.String(), portaPortalCativo)
	if err := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-s", ip, "-p", "tcp", "--dport", "80",
		"-j", "DNAT", "--to-destination", destinoHTTP,
	).Run(); err != nil {
		return err
	}
	destinoHTTPS := net.JoinHostPort(rede.IP.String(), portaPortalCativoTLS)
	return exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-s", ip, "-p", "tcp", "--dport", "443",
		"-j", "DNAT", "--to-destination", destinoHTTPS,
	).Run()
}

// desativarPortalCativo remove as regras criadas por ativarPortalCativo.
func desativarPortalCativo(ip string, rede *infoRede) {
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-s", ip, "-p", "tcp", "--dport", "80",
		"-j", "DNAT", "--to-destination", net.JoinHostPort(rede.IP.String(), portaPortalCativo),
	).Run()
	exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-s", ip, "-p", "tcp", "--dport", "443",
		"-j", "DNAT", "--to-destination", net.JoinHostPort(rede.IP.String(), portaPortalCativoTLS),
	).Run()
}

// limparRegrasOrfas detecta e remove regras de DROP no iptables que
// sobraram de uma execução anterior do Sentinela. Se o programa cair
// ou for morto (Ctrl+C, crash, kill -9) enquanto algo está isolado, o
// ARP spoofing para na hora (era só uma goroutine em memória), mas a
// regra no firewall — que só é removida quando alguém clica
// "reconectar" — continua bloqueando o dispositivo pra sempre, mesmo
// depois do dashboard reiniciar do zero e mostrar ele como "não
// isolado". Roda uma vez, ao iniciar.
func limparRegrasOrfas(rede *infoRede) {
	saida, err := exec.Command("iptables", "-L", "FORWARD", "-n").Output()
	if err != nil {
		return
	}

	orfaos := make(map[string]bool)
	for _, linha := range strings.Split(string(saida), "\n") {
		campos := strings.Fields(linha)
		if len(campos) < 5 || campos[0] != "DROP" {
			continue
		}
		for _, ip := range []string{campos[3], campos[4]} {
			candidato := net.ParseIP(ip)
			if candidato == nil || !rede.IPNet.Contains(candidato) {
				continue
			}
			if ip == rede.IP.String() || ip == rede.Gateway.String() {
				continue
			}
			orfaos[ip] = true
		}
	}

	for ip := range orfaos {
		for exec.Command("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP").Run() == nil {
			// -D remove só uma ocorrência por chamada; repete até não sobrar nenhuma
		}
		for exec.Command("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP").Run() == nil {
		}
		fmt.Printf("Limpei uma regra de bloqueio órfã de %s (sobrou de uma execução anterior do programa)\n", ip)
		registrarEvento("limpeza_orfa", ip, "Regra de bloqueio órfã removida do iptables ao iniciar — provavelmente o programa foi encerrado enquanto esse dispositivo estava isolado.")
	}
}

// bloqueioIPv4Ativo confere (com "iptables -C", que só checa se a regra
// existe, sem alterar nada) se as regras de DROP desse IP continuam lá.
// Isso é o que diferencia "diz que isolou" de "provou que ainda está
// isolado" — um `iptables -F` manual, um reinício do firewall, ou
// qualquer outro processo mexendo nas regras não vai passar batido: o
// dashboard mostraria "isolado" mesmo com o bloqueio derrubado se só
// confiasse no mapa em memória.
func bloqueioIPv4Ativo(ip string) bool {
	origem := exec.Command("iptables", "-C", "FORWARD", "-s", ip, "-j", "DROP").Run() == nil
	destino := exec.Command("iptables", "-C", "FORWARD", "-d", ip, "-j", "DROP").Run() == nil
	return origem && destino
}

// pacotesBloqueados lê o contador de pacotes que o próprio kernel já
// mantém pra cada regra do iptables (`-v -x` mostra o valor exato, sem
// arredondar pra "K"/"M") e soma as duas regras (origem e destino)
// desse IP. É prova em número, ao vivo, de que o bloqueio não é só
// decorativo — cada tentativa do dispositivo isolado de falar com a
// rede aparece aqui.
func pacotesBloqueados(ip string) int64 {
	saida, err := exec.Command("iptables", "-L", "FORWARD", "-v", "-x", "-n").Output()
	if err != nil {
		return 0
	}
	var total int64
	for _, linha := range strings.Split(string(saida), "\n") {
		campos := strings.Fields(linha)
		if len(campos) < 9 || campos[2] != "DROP" {
			continue
		}
		origem, destino := campos[7], campos[8]
		if origem != ip && destino != ip {
			continue
		}
		if n, err := strconv.ParseInt(campos[0], 10, 64); err == nil {
			total += n
		}
	}
	return total
}

// bloqueioIPv6Ativo confere se a regra de ip6tables por MAC ainda existe.
func bloqueioIPv6Ativo(mac net.HardwareAddr) bool {
	return exec.Command("ip6tables", "-C", "FORWARD", "-m", "mac", "--mac-source", mac.String(), "-j", "DROP").Run() == nil
}

// iniciarCapturaTrafego aproveita que o ARP spoofing já faz o
// dispositivo isolado mandar seus pacotes pro notebook (pensando que é
// o gateway) pra registrar o que ele tentou acessar antes do iptables
// derrubar — sem isso, "isolei o dispositivo" fica sem nenhuma prova
// do que ele estava tentando fazer. É inteligência de ameaça de graça,
// só olhando o tráfego que já passa por aqui mesmo.
func iniciarCapturaTrafego(handle *pcap.Handle, ip string, alvoMAC net.HardwareAddr) {
	if err := handle.SetBPFFilter(fmt.Sprintf("ether src %s", alvoMAC.String())); err != nil {
		return // segue sem captura — não é crítico pro isolamento em si
	}

	const limiteDestinos = 20
	vistos := make(map[string]bool, limiteDestinos)
	var vistosMu sync.Mutex

	fonte := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		for pacote := range fonte.Packets() {
			camadaRede := pacote.NetworkLayer()
			if camadaRede == nil {
				continue
			}
			destino := camadaRede.NetworkFlow().Dst().String()

			var descricao string
			if dnsCamada := pacote.Layer(layers.LayerTypeDNS); dnsCamada != nil {
				if dns, ok := dnsCamada.(*layers.DNS); ok && len(dns.Questions) > 0 {
					descricao = fmt.Sprintf("tentou resolver DNS: %s", dns.Questions[0].Name)
				}
			}
			if descricao == "" {
				switch {
				case pacote.Layer(layers.LayerTypeTCP) != nil:
					tcp := pacote.Layer(layers.LayerTypeTCP).(*layers.TCP)
					descricao = fmt.Sprintf("tentou conectar em %s:%s (TCP)", destino, tcp.DstPort)
				case pacote.Layer(layers.LayerTypeUDP) != nil:
					udp := pacote.Layer(layers.LayerTypeUDP).(*layers.UDP)
					descricao = fmt.Sprintf("tentou conectar em %s:%s (UDP)", destino, udp.DstPort)
				default:
					continue // nem TCP, UDP ou DNS — ignora
				}
			}

			vistosMu.Lock()
			if vistos[descricao] || len(vistos) >= limiteDestinos {
				vistosMu.Unlock()
				continue
			}
			vistos[descricao] = true
			vistosMu.Unlock()

			registrarEvento("trafego_bloqueado", ip, descricao)
		}
	}()
}

// isolarDispositivo começa a envenenar a tabela ARP do dispositivo-alvo
// e do gateway, fazendo cada um pensar que o outro é o notebook, e
// bloqueia via iptables o encaminhamento desse IP no FORWARD — sem essa
// segunda parte, o kernel (com ip_forward ligado pelo Docker) repassaria
// o tráfego de qualquer jeito e o dispositivo continuaria com internet.
// isolarDispositivo isola o dispositivo por tempo indeterminado se
// duracao for 0, ou automaticamente reconecta sozinho depois de
// duracao (ver iniciarVigiaTimeoutIsolamento) — evita esquecer um
// dispositivo bloqueado pra sempre depois de um teste.
func isolarDispositivo(rede *infoRede, alvoIP net.IP, alvoMAC net.HardwareAddr, duracao time.Duration) error {
	ip := alvoIP.String()

	isolamentosMu.Lock()
	if _, jaAtivo := isolamentos[ip]; jaAtivo {
		isolamentosMu.Unlock()
		return fmt.Errorf("%s já está isolado", ip)
	}
	isolamentosMu.Unlock()

	handle, err := pcap.OpenLive(rede.Interface, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("não consegui abrir a interface %s pra enviar ARP (rode como root): %w", rede.Interface, err)
	}

	if err := bloquearEncaminhamento(ip, alvoMAC); err != nil {
		handle.Close()
		return fmt.Errorf("não consegui bloquear o encaminhamento de %s no iptables (rode como root): %w", ip, err)
	}
	// best-effort: sem o portal cativo o dispositivo só fica sem
	// internet, sem explicação — pior experiência, mas não é motivo
	// pra falhar o isolamento inteiro se o DNAT não puder ser criado.
	_ = ativarPortalCativo(ip, rede)

	ctx, cancel := context.WithCancel(context.Background())
	estado := &isolamentoAtivo{cancelar: cancel, desde: time.Now(), mac: alvoMAC}
	if duracao > 0 {
		estado.expiraEm = time.Now().Add(duracao)
	}

	isolamentosMu.Lock()
	isolamentos[ip] = estado
	isolamentosMu.Unlock()

	detalheEvento := "Isolamento por ARP spoofing iniciado"
	if duracao > 0 {
		detalheEvento += fmt.Sprintf(" (reconecta sozinho em %s, se ninguém mexer antes)", duracao)
	} else {
		detalheEvento += " (sem prazo — fica isolado até reconectar manualmente)"
	}
	if rede.GatewayIPv6 != nil {
		detalheEvento += " — com bloqueio de rota IPv6 via Router Advertisement falso"
	}
	detalheEvento += " — tráfego HTTP redirecionado pro portal cativo explicando o motivo"
	registrarEvento("isolado", ip, detalheEvento)

	iniciarCapturaTrafego(handle, ip, alvoMAC)

	go func() {
		defer handle.Close()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			// diz pro alvo: "o gateway sou eu"
			enviarARPReply(handle, rede.MAC, alvoMAC, rede.MAC, rede.Gateway, alvoMAC, alvoIP)
			// diz pro gateway: "o alvo sou eu" (corta os dois sentidos)
			enviarARPReply(handle, rede.MAC, rede.GatewayMAC, rede.MAC, alvoIP, rede.GatewayMAC, rede.Gateway)
			atomic.AddInt64(&estado.pacotes, 2)
			// derruba a rota padrão IPv6 do alvo, forçando fallback pra IPv4 (já bloqueado)
			if rede.GatewayIPv6 != nil {
				enviarRABloqueio(handle, rede.MAC, alvoMAC, rede.GatewayIPv6)
			}

			select {
			case <-ctx.Done():
				restaurarARP(handle, rede, alvoIP, alvoMAC)
				return
			case <-ticker.C:
			}
		}
	}()

	return nil
}

// restaurarARP avisa o alvo e o gateway do mapeamento IP->MAC
// verdadeiro, pra rede voltar ao normal sem precisar esperar o
// tempo de expiração natural da tabela ARP.
func restaurarARP(handle *pcap.Handle, rede *infoRede, alvoIP net.IP, alvoMAC net.HardwareAddr) {
	for i := 0; i < 4; i++ {
		enviarARPReply(handle, rede.GatewayMAC, alvoMAC, rede.GatewayMAC, rede.Gateway, alvoMAC, alvoIP)
		enviarARPReply(handle, alvoMAC, rede.GatewayMAC, alvoMAC, alvoIP, rede.GatewayMAC, rede.Gateway)
		time.Sleep(300 * time.Millisecond)
	}
}

func reconectarDispositivo(ip string, rede *infoRede) error {
	isolamentosMu.Lock()
	estado, ok := isolamentos[ip]
	if ok {
		delete(isolamentos, ip)
	}
	isolamentosMu.Unlock()

	if !ok {
		return fmt.Errorf("%s não está isolado", ip)
	}
	estado.cancelar()
	liberarEncaminhamento(ip, estado.mac)
	desativarPortalCativo(ip, rede)
	registrarEvento("reconectado", ip, "Isolamento cancelado, dispositivo reconectado à rede principal")
	return nil
}

// iniciarVigiaTimeoutIsolamento confere periodicamente se algum
// isolamento com prazo definido já venceu, e reconecta sozinho. Roda
// de segundo em segundo plano desde o início do programa (não só
// quando alguém abre o dashboard).
func iniciarVigiaTimeoutIsolamento(rede *infoRede) {
	go func() {
		for {
			time.Sleep(30 * time.Second)

			isolamentosMu.Lock()
			var expirados []string
			agora := time.Now()
			for ip, estado := range isolamentos {
				if !estado.expiraEm.IsZero() && agora.After(estado.expiraEm) {
					expirados = append(expirados, ip)
				}
			}
			isolamentosMu.Unlock()

			for _, ip := range expirados {
				if err := reconectarDispositivo(ip, rede); err == nil {
					registrarEvento("timeout_isolamento", ip, "O prazo de isolamento definido na hora de isolar venceu — dispositivo reconectado automaticamente.")
				}
			}
		}
	}()
}
