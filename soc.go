package main

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// ---------- triage: severity and correlation ----------

// Every event used to land in one flat list with the same visual weight,
// so a device that merely came back online sat beside a containment that
// silently failed. Without a severity there is nothing to triage by, and
// without correlation a rogue DHCP server and an ARP spoof coming from
// the same address read as two loose events instead of one incident.
type severity int

const (
	sevInfo severity = iota
	sevLow
	sevMedium
	sevHigh
)

func (s severity) label() string {
	switch s {
	case sevHigh:
		return "Crítico"
	case sevMedium:
		return "Atenção"
	case sevLow:
		return "Baixo"
	default:
		return "Informativo"
	}
}

// colour returns the CSS custom property for this severity. Info and low
// deliberately use plain ink: reserving colour for what needs action is
// what keeps the colour meaningful.
func (s severity) colour() string {
	switch s {
	case sevHigh:
		return "var(--risk-alto)"
	case sevMedium:
		return "var(--risk-medio)"
	case sevLow:
		return "var(--ink-2)"
	default:
		return "var(--ink-3)"
	}
}

// eventSeverity is derived from the event type rather than stored, so the
// events already on disk get a severity too, with no migration.
var eventSeverity = map[string]severity{
	// an attack under way, or a defence that stopped working
	"alerta_arp_spoofing":  sevHigh,
	"alerta_arp_duplicado": sevHigh,
	"alerta_dhcp_falso":    sevHigh,
	"alerta_evil_twin":     sevHigh,
	"alerta_evasao":        sevHigh,
	"alerta_bloqueio":      sevHigh,

	// worth looking at, not necessarily an attack
	"alerta_conflito_ip": sevMedium,
	"alerta_saude_rede":  sevMedium,
	"upnp_exposicao":     sevMedium,
	"porta_nova":         sevMedium,
	"nac_negado":         sevMedium,
	"nac_falhou":         sevHigh,
	"nac_simulado":       sevLow,
	"isolado":            sevMedium,

	// routine bookkeeping
	"mudanca_risco": sevLow,
	"limpeza_orfa":  sevLow,
}

func severityOf(eventType string) severity {
	if s, ok := eventSeverity[eventType]; ok {
		return s
	}
	return sevInfo
}

// attackEvents are the kinds that point at someone acting on the network,
// as opposed to the network simply changing. Only these open an incident.
var attackEvents = map[string]bool{
	"alerta_arp_spoofing":  true,
	"alerta_arp_duplicado": true,
	"alerta_dhcp_falso":    true,
	"alerta_evil_twin":     true,
	"alerta_evasao":        true,
	"alerta_bloqueio":      true,
	"alerta_conflito_ip":   true,
}

// incidentWindow is how far back correlation looks. Long enough to tie a
// staged attack together, short enough that yesterday's noise does not
// keep an incident open forever.
const incidentWindow = 30 * time.Minute

// incident groups everything recently seen against one address. Two
// distinct kinds of attack against the same target is the signal worth
// escalating: one alert can be a glitch, two of different kinds rarely is.
type incident struct {
	IP        string
	Kinds     []string
	Count     int
	Last      time.Time
	Escalated bool
}

func openIncidents() []incident {
	historyMu.Lock()
	events := make([]historyEvent, len(historyInMemory))
	copy(events, historyInMemory)
	historyMu.Unlock()

	cutoff := time.Now().Add(-incidentWindow)
	byTarget := map[string]*incident{}
	kindSeen := map[string]map[string]bool{}

	for _, e := range events {
		if e.When.Before(cutoff) || !attackEvents[e.Type] || e.IP == "" {
			continue
		}
		inc, ok := byTarget[e.IP]
		if !ok {
			inc = &incident{IP: e.IP}
			byTarget[e.IP] = inc
			kindSeen[e.IP] = map[string]bool{}
		}
		inc.Count++
		if e.When.After(inc.Last) {
			inc.Last = e.When
		}
		if !kindSeen[e.IP][e.Type] {
			kindSeen[e.IP][e.Type] = true
			inc.Kinds = append(inc.Kinds, e.Type)
		}
	}

	out := make([]incident, 0, len(byTarget))
	for _, inc := range byTarget {
		inc.Escalated = len(inc.Kinds) >= 2
		out = append(out, *inc)
	}
	// the escalated ones first, then the most recent
	sort.Slice(out, func(i, j int) bool {
		if out[i].Escalated != out[j].Escalated {
			return out[i].Escalated
		}
		return out[i].Last.After(out[j].Last)
	})
	return out
}

// incidentsBlockHTML is the triage panel: what needs attention right now,
// as opposed to the full history, which is the record of everything.
func incidentsBlockHTML() string {
	incidents := openIncidents()
	if len(incidents) == 0 {
		return panel("ok", "🛡️ Incidentes abertos",
			`<div class="meta">Nada nos últimos 30 minutos.</div>`)
	}

	var lines strings.Builder
	for _, inc := range incidents {
		var kinds []string
		for _, k := range inc.Kinds {
			label := eventLabel[k]
			if label == "" {
				label = k
			}
			kinds = append(kinds, html.EscapeString(label))
		}
		mark := ""
		if inc.Escalated {
			mark = ` <b>· correlacionado</b>`
		}
		lines.WriteString(fmt.Sprintf("<li><b>%s</b> — %s%s <span class=\"mac\">(%s)</span></li>",
			html.EscapeString(inc.IP), strings.Join(kinds, " + "), mark, formatWhen(inc.Last)))
	}
	return panel("warn", fmt.Sprintf("🛡️ Incidentes abertos (%d)", len(incidents)),
		"<ul>"+lines.String()+"</ul>")
}
