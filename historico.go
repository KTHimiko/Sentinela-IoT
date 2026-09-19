package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// ---------- histórico de eventos ----------

// eventoHistorico registra algo que aconteceu na rede: um dispositivo
// novo, um dispositivo que sumiu, uma mudança de risco, um isolamento
// ou reconexão. É a "memória" do NOC — sem isso, cada scan é um
// instantâneo isolado e não dá pra provar o que aconteceu com o tempo.
type eventoHistorico struct {
	Quando  time.Time
	Tipo    string
	IP      string
	Detalhe string
}

const arquivoHistorico = "historico.jsonl"
const tamanhoMaxHistoricoMem = 200

var historicoMu sync.Mutex
var historicoMem []eventoHistorico

var rotuloEvento = map[string]string{
	"novo_dispositivo":       "🆕 Novo dispositivo",
	"dispositivo_voltou":     "🔁 Dispositivo conhecido reapareceu",
	"dispositivo_saiu":       "👋 Dispositivo saiu da rede",
	"alerta_arp_duplicado":   "🚨 MAC duplicado (possível ARP poisoning)",
	"mudanca_risco":          "⚠️ Mudança de risco",
	"isolado":                "🔒 Isolado",
	"reconectado":            "🔓 Reconectado",
	"alerta_bloqueio":        "🚨 Bloqueio caiu sozinho",
	"alerta_arp_spoofing":    "🚨 Possível ataque ARP spoofing",
	"arp_spoofing_resolvido": "✅ ARP spoofing resolvido",
	"upnp_exposicao":         "🌐 Exposição UPnP detectada",
	"alerta_conflito_ip":     "🚨 Conflito de IP / possível spoofing",
	"porta_nova":             "🔓 Nova porta aberta",
	"alerta_evasao":          "🕵️ Possível evasão de isolamento",
	"alerta_saude_rede":      "📉 Queda brusca de dispositivos ativos",
	"trafego_bloqueado":      "🕵️ Tentativa de tráfego bloqueada",
	"limpeza_orfa":           "🧹 Regra de bloqueio órfã removida",
	"alerta_evil_twin":       "🚨 Possível rede Wi-Fi falsa (evil twin)",
	"timeout_isolamento":     "⏱️ Isolamento expirou (reconectado automaticamente)",
	"alerta_dhcp_falso":      "🚨 Possível servidor DHCP falso (rogue DHCP)",
}

// registrarEvento guarda o evento em memória (pra exibir rápido no
// dashboard) e também num arquivo em disco (pra sobreviver a um
// reinício do programa e servir de prova/registro da contenção).
func registrarEvento(tipo, ip, detalhe string) {
	ev := eventoHistorico{Quando: time.Now(), Tipo: tipo, IP: ip, Detalhe: detalhe}

	historicoMu.Lock()
	historicoMem = append(historicoMem, ev)
	if len(historicoMem) > tamanhoMaxHistoricoMem {
		historicoMem = historicoMem[len(historicoMem)-tamanhoMaxHistoricoMem:]
	}
	historicoMu.Unlock()

	arquivo, err := os.OpenFile(arquivoHistorico, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer arquivo.Close()
	if linha, err := json.Marshal(ev); err == nil {
		arquivo.Write(append(linha, '\n'))
	}
}

// carregarHistorico lê os eventos já gravados em disco (de execuções
// anteriores) pra memória, mantendo só os mais recentes. Assim um
// reinício do dashboard não perde o histórico recente.
func carregarHistorico() {
	arquivo, err := os.Open(arquivoHistorico)
	if err != nil {
		return
	}
	defer arquivo.Close()

	var eventos []eventoHistorico
	scanner := bufio.NewScanner(arquivo)
	for scanner.Scan() {
		var ev eventoHistorico
		if json.Unmarshal(scanner.Bytes(), &ev) == nil {
			eventos = append(eventos, ev)
		}
	}
	if len(eventos) > tamanhoMaxHistoricoMem {
		eventos = eventos[len(eventos)-tamanhoMaxHistoricoMem:]
	}

	historicoMu.Lock()
	historicoMem = eventos
	historicoMu.Unlock()
}
