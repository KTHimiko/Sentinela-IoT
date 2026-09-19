package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ---------- identification through mDNS/SSDP ----------

// Plenty of home IoT devices announce themselves on the network over mDNS
// (port 5353) — a bulb, a Chromecast, a printer, all of them periodically
// shout the kind of service they offer with nobody asking. That is a much
// stronger signal than the MAC OUI or the hostname for answering "this
// really is a smart bulb". Instead of implementing a full DNS parser (mDNS
// uses the raw DNS packet format), we only look for the service-type
// markers as plain text inside the packet: they show up as a readable
// substring even among the binary bytes, because DNS-SD service names are
// just sequences of ASCII labels.
var mdnsServiceMarkers = []struct{ marker, deviceType string }{
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

func identifyByMDNSPacket(packet []byte) string {
	text := string(packet)
	for _, m := range mdnsServiceMarkers {
		if strings.Contains(text, m.marker) {
			return m.deviceType
		}
	}
	return ""
}

var mdnsMu sync.RWMutex
var mdnsTypeByIP = make(map[string]string)

func typeByMDNS(ip string) string {
	mdnsMu.RLock()
	defer mdnsMu.RUnlock()
	return mdnsTypeByIP[ip]
}

// startMDNSListener joins the multicast group every mDNS device uses
// (224.0.0.251:5353) and passively listens to the announcements already
// circulating on the network — it never asks anything, it only listens.
// If the port is already taken (common: Linux usually runs an mDNS service
// such as Avahi or systemd-resolved), it gives up without holding back the
// rest of the program.
func startMDNSListener(iface string) {
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
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if deviceType := identifyByMDNSPacket(buf[:n]); deviceType != "" {
				mdnsMu.Lock()
				mdnsTypeByIP[from.IP.String()] = deviceType
				mdnsMu.Unlock()
			}
		}
	}()
}

// SSDP (the same language we already speak to the router to find UPnP
// exposure) is also used by other devices around the house — smart TVs,
// speakers, cameras — to announce what they are. Here the search is broad
// (ST: ssdp:all) and looks at the text of any reply, not just the router's.
var ssdpTextMarkers = []struct{ marker, deviceType string }{
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

func identifyBySSDPText(text string) string {
	t := strings.ToLower(text)
	for _, m := range ssdpTextMarkers {
		if strings.Contains(t, m.marker) {
			return m.deviceType
		}
	}
	return ""
}

// generalSSDPScan sends a broad M-SEARCH (ssdp:all, rather than looking
// only for the router) and collects the type of any device that answers
// inside the time window.
func generalSSDPScan() map[string]string {
	result := make(map[string]string)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return result
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	target := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	search := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(search), target); err != nil {
		return result
	}

	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout — no more replies
		}
		if deviceType := identifyBySSDPText(string(buf[:n])); deviceType != "" {
			result[from.IP.String()] = deviceType
		}
	}
	return result
}

var ssdpMu sync.RWMutex
var ssdpTypeByIP = make(map[string]string)

func typeBySSDP(ip string) string {
	ssdpMu.RLock()
	defer ssdpMu.RUnlock()
	return ssdpTypeByIP[ip]
}

// startSSDPProbe repeats generalSSDPScan periodically (it is
// request/response, unlike mDNS which listens on its own) and refreshes
// the cache used for type identification.
func startSSDPProbe() {
	go func() {
		for {
			result := generalSSDPScan()
			ssdpMu.Lock()
			for ip, deviceType := range result {
				ssdpTypeByIP[ip] = deviceType
			}
			ssdpMu.Unlock()
			time.Sleep(2 * time.Minute)
		}
	}()
}
