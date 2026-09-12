package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ---------- identificação via mDNS/SSDP ----------

// Muito dispositivo IoT doméstico se anuncia sozinho na rede via mDNS
// (porta 5353) — lâmpada, Chromecast, impressora, tudo isso "grita"
// periodicamente o tipo de serviço que oferece, sem precisar de
// ninguém perguntar. É um sinal bem mais forte que MAC OUI ou
// hostname pra responder "isso é uma lâmpada inteligente de verdade".
// Em vez de implementar um parser de DNS completo (mDNS usa o formato
// de pacote DNS raw), procuramos só pelos marcadores de tipo de
// serviço em texto puro dentro do pacote — eles aparecem como
// substring legível mesmo dentro dos bytes binários, porque nomes de
// serviço DNS-SD são só sequências de rótulos ASCII.
var marcadoresServicoMDNS = []struct{ marcador, tipo string }{
	{"_googlecast._tcp", "🔊 Assistente virtual / streaming (Chromecast/Google)"},
	{"_airplay._tcp", "🔊 Assistente virtual / streaming (AirPlay)"},
	{"_raop._tcp", "🔊 Assistente virtual / streaming (AirPlay áudio)"},
	{"_spotify-connect._tcp", "🔊 Assistente virtual / streaming (Spotify Connect)"},
	{"_hap._tcp", "💡 Dispositivo IoT (compatível com Apple HomeKit)"},
	{"_ipp._tcp", "🖨️ Impressora"},
	{"_printer._tcp", "🖨️ Impressora"},
	{"_pdl-datastream._tcp", "🖨️ Impressora"},
	{"_smb._tcp", "💻 Computador (compartilhamento de arquivos)"},
	{"_ssh._tcp", "💻 Computador/servidor (SSH)"},
	{"_workstation._tcp", "💻 Computador"},
	{"_home-sharing._tcp", "📺 Smart TV / media player"},
}

func identificarPorPacoteMDNS(pacote []byte) string {
	texto := string(pacote)
	for _, m := range marcadoresServicoMDNS {
		if strings.Contains(texto, m.marcador) {
			return m.tipo
		}
	}
	return ""
}

var mdnsMu sync.RWMutex
var mdnsTipoPorIP = make(map[string]string)

func tipoPorMDNS(ip string) string {
	mdnsMu.RLock()
	defer mdnsMu.RUnlock()
	return mdnsTipoPorIP[ip]
}

// iniciarEscutaMDNS entra no grupo multicast que todo dispositivo mDNS
// usa (224.0.0.251:5353) e fica passivamente ouvindo os anúncios que
// já circulam na rede sozinhos — não manda nenhuma pergunta, só
// escuta. Se a porta já estiver em uso (comum: o Linux já roda um
// serviço de mDNS tipo Avahi/systemd-resolved), desiste sem travar o
// resto do programa.
func iniciarEscutaMDNS(iface string) {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println("mDNS: interface não encontrada, identificação por mDNS desativada:", err)
		return
	}
	conn, err := net.ListenMulticastUDP("udp4", ni, &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353})
	if err != nil {
		fmt.Println("mDNS: não consegui escutar (provavelmente já tem outro serviço na porta 5353) — identificação por mDNS desativada:", err)
		return
	}
	go func() {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, origem, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if tipo := identificarPorPacoteMDNS(buf[:n]); tipo != "" {
				mdnsMu.Lock()
				mdnsTipoPorIP[origem.IP.String()] = tipo
				mdnsMu.Unlock()
			}
		}
	}()
}

// SSDP (a mesma "linguagem" que já falamos com o roteador pra achar
// exposição UPnP) também é usada por outros dispositivos da casa —
// Smart TVs, caixas de som, câmeras — pra anunciar o que são. Aqui a
// busca é ampla (ST: ssdp:all) e olha o texto de qualquer resposta,
// não só a do roteador.
var marcadoresTextoSSDP = []struct{ marcador, tipo string }{
	{"chromecast", "🔊 Assistente virtual / streaming (Chromecast/Google)"},
	{"sonos", "🔊 Assistente virtual / streaming (Sonos)"},
	{"roku", "🔊 Assistente virtual / streaming (Roku)"},
	{"philips hue", "💡 Dispositivo IoT (Philips Hue)"},
	{"hue bridge", "💡 Dispositivo IoT (Philips Hue)"},
	{"mediarenderer", "📺 Smart TV / media player"},
	{"smart tv", "📺 Smart TV"},
	{"printer", "🖨️ Impressora"},
	{"camera", "🎥 Câmera IP"},
}

func identificarPorTextoSSDP(texto string) string {
	t := strings.ToLower(texto)
	for _, m := range marcadoresTextoSSDP {
		if strings.Contains(t, m.marcador) {
			return m.tipo
		}
	}
	return ""
}

// escanearSSDPGeral manda um M-SEARCH amplo (ssdp:all, em vez de só
// procurar o roteador) e junta o tipo de qualquer dispositivo que
// responder dentro da janela de tempo.
func escanearSSDPGeral() map[string]string {
	resultado := make(map[string]string)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return resultado
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	destino := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	busca := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(busca), destino); err != nil {
		return resultado
	}

	buf := make([]byte, 2048)
	for {
		n, origem, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout — acabaram as respostas
		}
		if tipo := identificarPorTextoSSDP(string(buf[:n])); tipo != "" {
			resultado[origem.IP.String()] = tipo
		}
	}
	return resultado
}

var ssdpMu sync.RWMutex
var ssdpTipoPorIP = make(map[string]string)

func tipoPorSSDP(ip string) string {
	ssdpMu.RLock()
	defer ssdpMu.RUnlock()
	return ssdpTipoPorIP[ip]
}

// iniciarSondagemSSDP repete escanearSSDPGeral periodicamente (é
// pergunta/resposta, diferente do mDNS que já escuta sozinho) e
// atualiza o cache usado na identificação de tipo.
func iniciarSondagemSSDP() {
	go func() {
		for {
			resultado := escanearSSDPGeral()
			ssdpMu.Lock()
			for ip, tipo := range resultado {
				ssdpTipoPorIP[ip] = tipo
			}
			ssdpMu.Unlock()
			time.Sleep(2 * time.Minute)
		}
	}()
}
