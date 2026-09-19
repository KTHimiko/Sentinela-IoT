package main

import (
	"fmt"
	"net"
	"sync"
)

// ---------- detecção de ARP spoofing de terceiros ----------

// arpSpoofMu protege gatewayMACSuspeito: o último MAC "errado" que já
// vimos no lugar do gateway, pra alertar só na transição (quando o MAC
// muda) em vez de todo ciclo de varredura enquanto o ataque continuar.
var arpSpoofMu sync.Mutex
var gatewayMACSuspeito string

// verificarSpoofingDoGateway compara o MAC que a tabela ARP do próprio
// notebook mostra pro IP do gateway com o MAC verdadeiro (descoberto
// uma vez em detectarRede, no início). O programa também faz ARP
// spoofing (pra isolar dispositivos), mas isso nunca reescreve a
// entrada do gateway na tabela ARP do próprio notebook — só na do alvo
// isolado e na do roteador — então uma mudança aqui é sinal de que
// OUTRO dispositivo na rede está fazendo um ataque de ARP spoofing de
// verdade (ex: um notebook de visitante rodando Ettercap/Bettercap).
func verificarSpoofingDoGateway(rede *infoRede, tabelaARP map[string]net.HardwareAddr) {
	macAtual, ok := tabelaARP[rede.Gateway.String()]
	if !ok {
		return
	}
	atual := macAtual.String()
	esperado := rede.GatewayMAC.String()

	arpSpoofMu.Lock()
	defer arpSpoofMu.Unlock()

	if atual == esperado {
		if gatewayMACSuspeito != "" {
			registrarEvento("arp_spoofing_resolvido", rede.Gateway.String(),
				fmt.Sprintf("O MAC do gateway voltou ao valor esperado (%s).", esperado))
			gatewayMACSuspeito = ""
		}
		return
	}

	if atual != gatewayMACSuspeito {
		registrarEvento("alerta_arp_spoofing", rede.Gateway.String(),
			fmt.Sprintf("O MAC do gateway (%s) mudou pra %s — pode ser outro dispositivo na rede fazendo ARP spoofing (ataque man-in-the-middle)!", esperado, atual))
		gatewayMACSuspeito = atual
	}
}

// arpDupMu protege o conjunto de MACs já reportados como duplicados,
// pra alertar só na transição (quando o padrão aparece) e não a cada
// varredura enquanto ele persistir.
var arpDupMu sync.Mutex
var arpDuplicadosReportados = make(map[string]bool)

// detectarMACDuplicado procura, na tabela ARP do próprio notebook, um
// MAC que responde por dois ou mais IPs ao mesmo tempo. Um dispositivo
// legítimo tem um MAC por interface, então esse padrão é a assinatura
// clássica de ARP poisoning: o atacante se anuncia como sendo vários
// hosts de uma vez pra interceptar o tráfego deles. O gateway é
// ignorado porque seu spoofing já é coberto por
// verificarSpoofingDoGateway, e o MAC do próprio notebook também, já
// que é ele quem faz o spoofing de isolamento.
func detectarMACDuplicado(rede *infoRede, tabelaARP map[string]net.HardwareAddr) {
	ipsPorMAC := make(map[string][]string)
	nossoMAC := ""
	if rede.MAC != nil {
		nossoMAC = rede.MAC.String()
	}
	gatewayMAC := rede.GatewayMAC.String()
	for ip, mac := range tabelaARP {
		m := mac.String()
		if m == nossoMAC || m == gatewayMAC || ip == rede.Gateway.String() {
			continue
		}
		ipsPorMAC[m] = append(ipsPorMAC[m], ip)
	}

	for mac, ips := range ipsPorMAC {
		arpDupMu.Lock()
		jaReportado := arpDuplicadosReportados[mac]
		if len(ips) >= 2 {
			if !jaReportado {
				arpDuplicadosReportados[mac] = true
				arpDupMu.Unlock()
				registrarEvento("alerta_arp_duplicado", ips[0], fmt.Sprintf(
					"O mesmo MAC (%s) está respondendo por %d IPs ao mesmo tempo (%v) — um dispositivo legítimo tem um MAC por interface, então isso é sinal de ARP poisoning tentando interceptar o tráfego desses hosts.", mac, len(ips), ips))
				continue
			}
		} else if jaReportado {
			delete(arpDuplicadosReportados, mac)
		}
		arpDupMu.Unlock()
	}
}
