package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ---------- verificação de exposição pra internet via UPnP ----------

// O risco doméstico mais comum não é o que se vê de dentro da LAN — é
// o próprio roteador abrindo portas pro mundo sozinho via UPnP, porque
// algum dispositivo (uma câmera, um DVR) pediu "acesso remoto" e o
// roteador simplesmente aceitou, sem avisar ninguém. Essa checagem
// fala UPnP/IGD (o protocolo que roteadores domésticos usam) direto
// pelo notebook, sem precisar entrar no painel do roteador.
type mapeamentoUPnP struct {
	Protocolo    string
	PortaExterna string
	IPInterno    string
	PortaInterna string
	Descricao    string
	Ativo        bool
}

type upnpService struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

type upnpRoot struct {
	Device upnpDevice `xml:"device"`
}

func encontrarControlURLUPnP(d upnpDevice) string {
	for _, s := range d.Services {
		if strings.Contains(s.ServiceType, "WANIPConnection") || strings.Contains(s.ServiceType, "WANPPPConnection") {
			return s.ControlURL
		}
	}
	for _, sub := range d.Devices {
		if achado := encontrarControlURLUPnP(sub); achado != "" {
			return achado
		}
	}
	return ""
}

// descobrirControlURLUPnP manda um SSDP M-SEARCH multicast (o jeito
// padrão de "gritar" na rede local perguntando quem é o roteador
// UPnP) e, com a resposta, baixa a descrição XML do dispositivo pra
// achar a URL de controle do serviço de mapeamento de portas.
func descobrirControlURLUPnP() (string, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	destino := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	busca := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(busca), destino); err != nil {
		return "", err
	}

	buf := make([]byte, 2048)
	var location string
	for location == "" {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout — nenhum roteador respondeu
		}
		for _, linha := range strings.Split(string(buf[:n]), "\r\n") {
			if strings.HasPrefix(strings.ToUpper(linha), "LOCATION:") {
				location = strings.TrimSpace(linha[len("LOCATION:"):])
				break
			}
		}
	}
	if location == "" {
		return "", fmt.Errorf("nenhum roteador respondeu ao SSDP (UPnP pode estar desligado — o que é bom sinal de segurança)")
	}

	resp, err := http.Get(location)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var raiz upnpRoot
	if err := xml.NewDecoder(resp.Body).Decode(&raiz); err != nil {
		return "", err
	}
	caminho := encontrarControlURLUPnP(raiz.Device)
	if caminho == "" {
		return "", fmt.Errorf("roteador não anuncia um serviço de mapeamento de portas (WANIPConnection)")
	}

	base, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	controlURL, err := base.Parse(caminho)
	if err != nil {
		return "", err
	}
	return controlURL.String(), nil
}

// consultarMapeamentoUPnP pede ao roteador a entrada de mapeamento de
// porta no índice dado (a API do UPnP IGD é assim: não existe "listar
// tudo", só "me dê a entrada N", e o roteador some quando índices
// acabam).
func consultarMapeamentoUPnP(controlURL string, indice int) (mapeamentoUPnP, bool, error) {
	envelope := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewPortMappingIndex>%d</NewPortMappingIndex>
</u:GetGenericPortMappingEntry>
</s:Body>
</s:Envelope>`, indice)

	req, err := http.NewRequest("POST", controlURL, strings.NewReader(envelope))
	if err != nil {
		return mapeamentoUPnP{}, false, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"`)

	cliente := &http.Client{Timeout: 3 * time.Second}
	resp, err := cliente.Do(req)
	if err != nil {
		return mapeamentoUPnP{}, false, err
	}
	defer resp.Body.Close()
	corpo, err := io.ReadAll(resp.Body)
	if err != nil {
		return mapeamentoUPnP{}, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return mapeamentoUPnP{}, false, nil // índice além do último mapeamento existente
	}

	var envelopeResp struct {
		Body struct {
			Resposta struct {
				PortaExterna string `xml:"NewExternalPort"`
				Protocolo    string `xml:"NewProtocol"`
				IPInterno    string `xml:"NewInternalClient"`
				PortaInterna string `xml:"NewInternalPort"`
				Ativo        string `xml:"NewEnabled"`
				Descricao    string `xml:"NewPortMappingDescription"`
			} `xml:"GetGenericPortMappingEntryResponse"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(corpo, &envelopeResp); err != nil {
		return mapeamentoUPnP{}, false, err
	}
	r := envelopeResp.Body.Resposta
	if r.PortaExterna == "" {
		return mapeamentoUPnP{}, false, nil
	}
	return mapeamentoUPnP{
		Protocolo:    r.Protocolo,
		PortaExterna: r.PortaExterna,
		IPInterno:    r.IPInterno,
		PortaInterna: r.PortaInterna,
		Descricao:    r.Descricao,
		Ativo:        r.Ativo == "1",
	}, true, nil
}

// verificarExposicaoUPnP devolve todos os mapeamentos de porta que o
// roteador tem ativos agora (cada um é uma porta acessível a partir da
// internet, apontando pra um dispositivo específico da LAN).
func verificarExposicaoUPnP() ([]mapeamentoUPnP, error) {
	controlURL, err := descobrirControlURLUPnP()
	if err != nil {
		return nil, err
	}
	var mapeamentos []mapeamentoUPnP
	for indice := 0; indice < 64; indice++ { // limite de segurança contra roteador respondendo infinito
		m, ok, err := consultarMapeamentoUPnP(controlURL, indice)
		if err != nil || !ok {
			break
		}
		mapeamentos = append(mapeamentos, m)
	}
	return mapeamentos, nil
}

var upnpMu sync.RWMutex
var upnpMapeamentos []mapeamentoUPnP
var upnpErro string
var upnpUltimaChecagem time.Time

func lerCacheUPnP() ([]mapeamentoUPnP, string, time.Time) {
	upnpMu.RLock()
	defer upnpMu.RUnlock()
	return upnpMapeamentos, upnpErro, upnpUltimaChecagem
}

// iniciarVerificacaoUPnP roda em segundo plano, num intervalo bem mais
// espaçado que a varredura de dispositivos (o roteador é um só e essa
// consulta pesa mais nele), e registra no histórico quando uma porta
// nova aparece exposta.
func iniciarVerificacaoUPnP() {
	go func() {
		primeira := true
		anterior := map[string]bool{}
		for {
			mapeamentos, err := verificarExposicaoUPnP()

			upnpMu.Lock()
			upnpMapeamentos = mapeamentos
			if err != nil {
				upnpErro = err.Error()
			} else {
				upnpErro = ""
			}
			upnpUltimaChecagem = time.Now()
			upnpMu.Unlock()

			atual := make(map[string]bool, len(mapeamentos))
			for _, m := range mapeamentos {
				chave := m.Protocolo + ":" + m.PortaExterna
				atual[chave] = true
				if !primeira && !anterior[chave] {
					registrarEvento("upnp_exposicao", m.IPInterno, fmt.Sprintf(
						"Roteador abriu a porta externa %s/%s pro dispositivo interno %s:%s via UPnP (%s)",
						m.Protocolo, m.PortaExterna, m.IPInterno, m.PortaInterna, m.Descricao))
				}
			}
			primeira = false
			anterior = atual

			time.Sleep(2 * time.Minute)
		}
	}()
}
