package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// ---------- event history ----------

// historyEvent records something that happened on the network: a new
// device, a device that disappeared, a risk change, an isolation or a
// reconnection. It is the NOC's memory — without it every scan is an
// isolated snapshot and there is no way to prove what happened over time.
//
// The JSON tags are in Portuguese on purpose: history.jsonl files written
// by earlier versions use those keys, and dropping the tags would silently
// orphan every event already on disk.
type historyEvent struct {
	When   time.Time `json:"Quando"`
	Type   string    `json:"Tipo"`
	IP     string    `json:"IP"`
	Detail string    `json:"Detalhe"`
}

const historyFile = "historico.jsonl"
const maxHistoryInMemory = 200

var historyMu sync.Mutex
var historyInMemory []historyEvent

// eventLabel maps the stored event type to what the user reads. The keys
// stay in Portuguese because they are persisted values, not identifiers:
// renaming them would break the lookup for every event already recorded.
var eventLabel = map[string]string{
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
	"metrica_contencao":      "⏱️ Tempo de contenção medido",
	"nac_negado":             "🚦 Isolado pela política de admissão",
	"nac_simulado":           "🚦 A política teria isolado (simulação)",
	"nac_falhou":             "⚠️ A política decidiu isolar mas não conseguiu",
}

// recordEvent keeps the event in memory (so the dashboard can render it
// quickly) and also appends it to a file on disk, so it survives a restart
// and works as evidence that the containment happened.
func recordEvent(eventType, ip, detail string) {
	ev := historyEvent{When: time.Now(), Type: eventType, IP: ip, Detail: detail}

	historyMu.Lock()
	historyInMemory = append(historyInMemory, ev)
	if len(historyInMemory) > maxHistoryInMemory {
		historyInMemory = historyInMemory[len(historyInMemory)-maxHistoryInMemory:]
	}
	historyMu.Unlock()

	file, err := os.OpenFile(historyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	if line, err := json.Marshal(ev); err == nil {
		file.Write(append(line, '\n'))
	}
}

// loadHistory reads the events already on disk (from previous runs) back
// into memory, keeping only the most recent ones, so restarting the
// dashboard does not lose the recent history.
func loadHistory() {
	file, err := os.Open(historyFile)
	if err != nil {
		return
	}
	defer file.Close()

	var events []historyEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var ev historyEvent
		if json.Unmarshal(scanner.Bytes(), &ev) == nil {
			events = append(events, ev)
		}
	}
	if len(events) > maxHistoryInMemory {
		events = events[len(events)-maxHistoryInMemory:]
	}

	historyMu.Lock()
	historyInMemory = events
	historyMu.Unlock()
}
