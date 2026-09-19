package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ---------- rogue DHCP server detection ----------

// The ARP spoofing we already detect (checkGatewaySpoofing) has to be
// aimed at one device at a time. A rogue DHCP server is more powerful: put
// a second server on the network and, if it answers faster than the real
// router, it hands a forged gateway and DNS to every new device that joins
// from then on — with no need to poison anyone's ARP. It is a classic
// network attack that none of our other detections covers.
var dhcpMu sync.Mutex
var knownDHCPServers = make(map[string]bool)
var dhcpLearningPeriod = true

// startRogueDHCPDetection passively listens to DHCP traffic (ports 67 and
// 68) and, during the first 60 seconds, learns which IPs already answer as
// servers on the network — that becomes the trust baseline, and it even
// copes with unusual setups that legitimately run more than one DHCP
// server, as long as they are active from the start. After that period,
// any new server showing up raises an alert.
func startRogueDHCPDetection(iface string) {
	handle, err := pcap.OpenLive(iface, 65536, false, pcap.BlockForever)
	if err != nil {
		fmt.Println("Detecção de DHCP falso desativada (não consegui abrir a interface):", err)
		return
	}
	if err := handle.SetBPFFilter("udp and (port 67 or port 68)"); err != nil {
		handle.Close()
		fmt.Println("Detecção de DHCP falso desativada (filtro BPF):", err)
		return
	}

	go func() {
		time.Sleep(60 * time.Second)
		dhcpMu.Lock()
		dhcpLearningPeriod = false
		total := len(knownDHCPServers)
		dhcpMu.Unlock()
		fmt.Printf("Detecção de DHCP falso: %d servidor(es) legítimo(s) identificado(s) na rede, monitorando por novos\n", total)
	}()

	go func() {
		defer handle.Close()
		source := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range source.Packets() {
			dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
			if dhcpLayer == nil {
				continue
			}
			dhcp, ok := dhcpLayer.(*layers.DHCPv4)
			if !ok || dhcp.Operation != layers.DHCPOpReply {
				continue // only server replies (OFFER/ACK) matter, not client requests
			}

			var msgType layers.DHCPMsgType
			var offeredGateway, offeredDNS string
			for _, opt := range dhcp.Options {
				switch opt.Type {
				case layers.DHCPOptMessageType:
					if len(opt.Data) == 1 {
						msgType = layers.DHCPMsgType(opt.Data[0])
					}
				case layers.DHCPOptRouter:
					if len(opt.Data) >= 4 {
						offeredGateway = net.IP(opt.Data[:4]).String()
					}
				case layers.DHCPOptDNS:
					if len(opt.Data) >= 4 {
						offeredDNS = net.IP(opt.Data[:4]).String()
					}
				}
			}
			if msgType != layers.DHCPMsgTypeOffer && msgType != layers.DHCPMsgTypeAck {
				continue
			}

			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}
			server := networkLayer.NetworkFlow().Src().String()

			dhcpMu.Lock()
			if dhcpLearningPeriod {
				knownDHCPServers[server] = true
				dhcpMu.Unlock()
				continue
			}
			known := knownDHCPServers[server]
			if !known {
				knownDHCPServers[server] = true
			}
			dhcpMu.Unlock()

			if !known {
				offer := ""
				if offeredGateway != "" {
					offer += fmt.Sprintf(" Está entregando o gateway %s", offeredGateway)
					if offeredDNS != "" {
						offer += fmt.Sprintf(" e o DNS %s", offeredDNS)
					}
					offer += " — se esse gateway/DNS não for o do roteador legítimo, o tráfego de novos dispositivos está sendo desviado."
				}
				recordEvent("alerta_dhcp_falso", server, fmt.Sprintf(
					"Um servidor DHCP novo (%s) começou a responder na rede — pode ser um roteador antigo religado por engano, ou um ataque de DHCP falso (rogue DHCP) tentando sequestrar o tráfego de novos dispositivos.%s", server, offer))
			}
		}
	}()
}
