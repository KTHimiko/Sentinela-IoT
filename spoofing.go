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
