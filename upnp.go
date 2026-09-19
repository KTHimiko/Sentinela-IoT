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

// ---------- checking exposure to the internet through UPnP ----------

// The most common risk at home is not what can be seen from inside the
// LAN — it is the router opening ports to the world on its own through
// UPnP, because some device (a camera, a DVR) asked for "remote access"
// and the router simply agreed, telling nobody. This check speaks
// UPnP/IGD (the protocol home routers use) straight from the laptop,
// without anyone having to log into the router's admin page.
type upnpMapping struct {
	Protocol     string
	ExternalPort string
	InternalIP   string
	InternalPort string
	Description  string
	Enabled      bool
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

func findUPnPControlURL(d upnpDevice) string {
	for _, s := range d.Services {
		if strings.Contains(s.ServiceType, "WANIPConnection") || strings.Contains(s.ServiceType, "WANPPPConnection") {
			return s.ControlURL
		}
	}
	for _, sub := range d.Devices {
		if found := findUPnPControlURL(sub); found != "" {
			return found
		}
	}
	return ""
}

// discoverUPnPControlURL sends a multicast SSDP M-SEARCH (the standard way
// of shouting on the local network asking which device is the UPnP router)
// and, from the reply, downloads the device's XML description to find the
// control URL of the port-mapping service.
func discoverUPnPControlURL() (string, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	target := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	search := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(search), target); err != nil {
		return "", err
	}

	buf := make([]byte, 2048)
	var location string
	for location == "" {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout — no router answered
		}
		for _, line := range strings.Split(string(buf[:n]), "\r\n") {
			if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
				location = strings.TrimSpace(line[len("LOCATION:"):])
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

	var root upnpRoot
	if err := xml.NewDecoder(resp.Body).Decode(&root); err != nil {
		return "", err
	}
	path := findUPnPControlURL(root.Device)
	if path == "" {
		return "", fmt.Errorf("roteador não anuncia um serviço de mapeamento de portas (WANIPConnection)")
	}

	base, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	controlURL, err := base.Parse(path)
	if err != nil {
		return "", err
	}
	return controlURL.String(), nil
}

// queryUPnPMapping asks the router for the port-mapping entry at the
// given index. The UPnP IGD API works that way: there is no "list
// everything", only "give me entry N", and the router stops answering once
// the indexes run out.
func queryUPnPMapping(controlURL string, index int) (upnpMapping, bool, error) {
	envelope := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewPortMappingIndex>%d</NewPortMappingIndex>
</u:GetGenericPortMappingEntry>
</s:Body>
</s:Envelope>`, index)

	req, err := http.NewRequest("POST", controlURL, strings.NewReader(envelope))
	if err != nil {
		return upnpMapping{}, false, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"`)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return upnpMapping{}, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return upnpMapping{}, false, err
	}
	if resp.StatusCode != http.StatusOK {
		return upnpMapping{}, false, nil // index past the last existing mapping
	}

	var responseEnvelope struct {
		Body struct {
			Response struct {
				ExternalPort string `xml:"NewExternalPort"`
				Protocol     string `xml:"NewProtocol"`
				InternalIP   string `xml:"NewInternalClient"`
				InternalPort string `xml:"NewInternalPort"`
				Enabled      string `xml:"NewEnabled"`
				Description  string `xml:"NewPortMappingDescription"`
			} `xml:"GetGenericPortMappingEntryResponse"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(body, &responseEnvelope); err != nil {
		return upnpMapping{}, false, err
	}
	r := responseEnvelope.Body.Response
	if r.ExternalPort == "" {
		return upnpMapping{}, false, nil
	}
	return upnpMapping{
		Protocol:     r.Protocol,
		ExternalPort: r.ExternalPort,
		InternalIP:   r.InternalIP,
		InternalPort: r.InternalPort,
		Description:  r.Description,
		Enabled:      r.Enabled == "1",
	}, true, nil
}

// checkUPnPExposure returns every port mapping the router currently has
// active. Each one is a port reachable from the internet, pointing at a
// specific device on the LAN.
func checkUPnPExposure() ([]upnpMapping, error) {
	controlURL, err := discoverUPnPControlURL()
	if err != nil {
		return nil, err
	}
	var mappings []upnpMapping
	for index := 0; index < 64; index++ { // safety limit against a router answering forever
		m, ok, err := queryUPnPMapping(controlURL, index)
		if err != nil || !ok {
			break
		}
		mappings = append(mappings, m)
	}
	return mappings, nil
}

var upnpMu sync.RWMutex
var upnpMappings []upnpMapping
var upnpError string
var upnpLastCheck time.Time

func readUPnPCache() ([]upnpMapping, string, time.Time) {
	upnpMu.RLock()
	defer upnpMu.RUnlock()
	return upnpMappings, upnpError, upnpLastCheck
}

// startUPnPCheck runs in the background on a much wider interval than the
// device scan (there is only one router and this query is heavier on it),
// and records in the history whenever a new port shows up exposed.
func startUPnPCheck() {
	go func() {
		first := true
		previous := map[string]bool{}
		for {
			mappings, err := checkUPnPExposure()

			upnpMu.Lock()
			upnpMappings = mappings
			if err != nil {
				upnpError = err.Error()
			} else {
				upnpError = ""
			}
			upnpLastCheck = time.Now()
			upnpMu.Unlock()

			current := make(map[string]bool, len(mappings))
			for _, m := range mappings {
				key := m.Protocol + ":" + m.ExternalPort
				current[key] = true
				if !first && !previous[key] {
					recordEvent("upnp_exposicao", m.InternalIP, fmt.Sprintf(
						"Roteador abriu a porta externa %s/%s pro dispositivo interno %s:%s via UPnP (%s)",
						m.Protocol, m.ExternalPort, m.InternalIP, m.InternalPort, m.Description))
				}
			}
			first = false
			previous = current

			time.Sleep(2 * time.Minute)
		}
	}()
}
