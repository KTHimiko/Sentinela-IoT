package main

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------- network health: latency and availability ----------

// Until now the only notion of network health was the alert for a sharp
// drop in the device count. Meanwhile every scan already pings every
// host and threw the round-trip time away. Keeping it costs nothing and
// answers the question a home user actually asks — "is the network slow?"
// — which the program had nothing to say about.
//
// Availability is counted in scan cycles rather than wall time: a device
// that answered 57 of the last 60 cycles is at 95%, and because the cycle
// is fixed that maps directly onto minutes.
const maxProbeSamples = 120

type hostHealth struct {
	rtts     []time.Duration
	answered int
	missed   int
	lastSeen time.Time
}

var healthMu sync.Mutex
var hostHealthByIP = map[string]*hostHealth{}

// recordProbe stores the outcome of one ping. A host that never answered
// is not tracked at all: recording a miss for each of the 254 addresses
// of an empty subnet would bury the real devices in noise. Only once a
// host has answered at least once do its later absences start counting.
func recordProbe(ip string, rtt time.Duration, answered bool) {
	healthMu.Lock()
	defer healthMu.Unlock()

	h, known := hostHealthByIP[ip]
	if !known {
		if !answered {
			return
		}
		h = &hostHealth{}
		hostHealthByIP[ip] = h
	}

	if !answered {
		h.missed++
		return
	}
	h.answered++
	h.lastSeen = time.Now()
	if rtt > 0 {
		h.rtts = append(h.rtts, rtt)
		if len(h.rtts) > maxProbeSamples {
			h.rtts = h.rtts[len(h.rtts)-maxProbeSamples:]
		}
	}
}

// healthOf returns the median round-trip time and the share of cycles the
// host answered. ok is false when there is nothing measured yet.
func healthOf(ip string) (median time.Duration, availability float64, ok bool) {
	healthMu.Lock()
	defer healthMu.Unlock()

	h, known := hostHealthByIP[ip]
	if !known || h.answered == 0 {
		return 0, 0, false
	}
	total := h.answered + h.missed
	availability = float64(h.answered) / float64(total)

	if len(h.rtts) == 0 {
		return 0, availability, true
	}
	sorted := make([]time.Duration, len(h.rtts))
	copy(sorted, h.rtts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2], availability, true
}

// healthSummary is one line of the NOC panel.
type healthSummary struct {
	IP           string
	Median       time.Duration
	Availability float64
}

// flakiestHosts returns the hosts worth complaining about: the ones that
// miss cycles. A device that is simply switched off is indistinguishable
// from one with a bad link, so the cut-off is deliberately generous —
// this is a hint to look, not a verdict.
func flakiestHosts(limit int) []healthSummary {
	healthMu.Lock()
	var out []healthSummary
	for ip, h := range hostHealthByIP {
		total := h.answered + h.missed
		if total < 5 || h.missed == 0 {
			continue // too early to say, or nothing to report
		}
		out = append(out, healthSummary{IP: ip, Availability: float64(h.answered) / float64(total)})
	}
	healthMu.Unlock()

	for i := range out {
		out[i].Median, _, _ = healthOf(out[i].IP)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Availability < out[j].Availability })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// gatewayHealthHTML plus the flaky list make up the NOC panel: how the
// link to the router is behaving, and who keeps dropping off.
func nocBlockHTML(network *networkInfo) string {
	gwMedian, gwAvailability, ok := healthOf(network.Gateway.String())
	if !ok {
		return panel("", "📡 Saúde da rede",
			`<div class="meta">Ainda sem medições — a primeira varredura completa alimenta este painel.</div>`)
	}

	class := "ok"
	verdict := "resposta do roteador dentro do esperado"
	switch {
	case gwAvailability < 0.9:
		class, verdict = "warn", "o roteador está deixando de responder a parte das sondagens"
	case gwMedian > 100*time.Millisecond:
		class, verdict = "warn", "resposta do roteador acima do normal para uma rede local"
	}

	body := fmt.Sprintf(
		`<div class="meta">Roteador <b>%s</b>: %s de latência, respondeu em %.0f%% das varreduras — %s.</div>`,
		html.EscapeString(network.Gateway.String()), formatDuration(gwMedian),
		gwAvailability*100, verdict)

	if flaky := flakiestHosts(5); len(flaky) > 0 {
		var lines strings.Builder
		for _, f := range flaky {
			latency := "sem medida"
			if f.Median > 0 {
				latency = formatDuration(f.Median)
			}
			lines.WriteString(fmt.Sprintf("<li>%s — respondeu em %.0f%% das varreduras (%s)</li>",
				html.EscapeString(f.IP), f.Availability*100, latency))
		}
		body += `<div class="meta" style="margin-top:.5rem">Aparelhos que somem e voltam:</div><ul>` +
			lines.String() + `</ul>`
	}

	return panel(class, "📡 Saúde da rede", body)
}
