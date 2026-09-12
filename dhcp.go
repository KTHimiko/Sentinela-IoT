package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ---------- detecção de servidor DHCP não autorizado ----------

// O ARP spoofing que já detectamos (verificarSpoofingDoGateway) exige
// atacar dispositivo por dispositivo. Um servidor DHCP falso (rogue
// DHCP) é mais poderoso: se alguém colocar um segundo servidor na rede
// e ele responder mais rápido que o roteador de verdade, ele entrega
// gateway/DNS forjado pra qualquer dispositivo novo que entrar na rede
// dali pra frente — sem precisar envenenar ARP de ninguém. É um ataque
// clássico de rede que nenhuma das nossas outras detecções cobre.
var dhcpMu sync.Mutex
var dhcpServidoresConhecidos = make(map[string]bool)
var dhcpPeriodoAprendizado = true

// iniciarDeteccaoDHCPFalso escuta passivamente o tráfego DHCP (portas
// 67/68) e, nos primeiros 60s, aprende quais IPs já respondem como
// servidor na rede — isso vira a "baseline" de confiança (dá conta até
// de setups incomuns com mais de um servidor DHCP legítimo, contanto
// que já estejam ativos desde o início). Depois desse período, qualquer
// servidor novo que apareça gera um alerta.
func iniciarDeteccaoDHCPFalso(iface string) {
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
		dhcpPeriodoAprendizado = false
		total := len(dhcpServidoresConhecidos)
		dhcpMu.Unlock()
		fmt.Printf("Detecção de DHCP falso: %d servidor(es) legítimo(s) identificado(s) na rede, monitorando por novos\n", total)
	}()

	go func() {
		defer handle.Close()
		fonte := gopacket.NewPacketSource(handle, handle.LinkType())
		for pacote := range fonte.Packets() {
			dhcpCamada := pacote.Layer(layers.LayerTypeDHCPv4)
			if dhcpCamada == nil {
				continue
			}
			dhcp, ok := dhcpCamada.(*layers.DHCPv4)
			if !ok || dhcp.Operation != layers.DHCPOpReply {
				continue // só nos interessa resposta de servidor (OFFER/ACK), não pedido de cliente
			}

			var tipo layers.DHCPMsgType
			for _, opt := range dhcp.Options {
				if opt.Type == layers.DHCPOptMessageType && len(opt.Data) == 1 {
					tipo = layers.DHCPMsgType(opt.Data[0])
				}
			}
			if tipo != layers.DHCPMsgTypeOffer && tipo != layers.DHCPMsgTypeAck {
				continue
			}

			camadaRede := pacote.NetworkLayer()
			if camadaRede == nil {
				continue
			}
			servidor := camadaRede.NetworkFlow().Src().String()

			dhcpMu.Lock()
			if dhcpPeriodoAprendizado {
				dhcpServidoresConhecidos[servidor] = true
				dhcpMu.Unlock()
				continue
			}
			jaConhecido := dhcpServidoresConhecidos[servidor]
			if !jaConhecido {
				dhcpServidoresConhecidos[servidor] = true
			}
			dhcpMu.Unlock()

			if !jaConhecido {
				registrarEvento("alerta_dhcp_falso", servidor, fmt.Sprintf(
					"Um servidor DHCP novo (%s) começou a responder na rede — pode ser um roteador antigo religado por engano, ou um ataque de DHCP falso (rogue DHCP) tentando sequestrar o tráfego de novos dispositivos.", servidor))
			}
		}
	}()
}
