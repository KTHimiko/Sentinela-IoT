package main

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// ---------- from risk to priority ----------

// On a real network the risk classification stopped sorting anything: 93
// of 131 devices came out "alto", because port 445 is open on every
// Windows machine in the building. The classification is not wrong —
// SMB exposed really is the WannaCry vector — but when almost everything
// scores the same, the score answers "is this dangerous in general?"
// when the question being asked is "which of these do I look at first?".
//
// So the intrinsic risk stays exactly as it is, tied to the service, and
// a separate priority is computed on top of it from two pieces of
// context the risk alone cannot see:
//
//   - reachable from the internet. A port mapped through UPnP on the
//     router is open to the world, not just to the living room. That is
//     a difference in kind, and the UPnP data was already being
//     collected without ever feeding the classification.
//
//   - how ordinary it is here. A port open on nearly every device is the
//     environment's baseline, not an anomaly. It still deserves the
//     "alto" label, but it is not where anyone should start, and saying
//     so out loud is more useful than listing ninety-three equals.
type priority int

const (
	prioRoutine priority = iota // the environment's normal
	prioReview                  // worth a look
	prioAct                     // reachable from outside
)

func (p priority) label() string {
	switch p {
	case prioAct:
		return "Agir"
	case prioReview:
		return "Revisar"
	default:
		return "Rotina"
	}
}

// ubiquityThreshold is the share of devices above which an open port
// counts as the environment's baseline rather than a finding. Two thirds
// is deliberately conservative: it takes a clear majority to excuse a
// port from attention.
const ubiquityThreshold = 0.66

// minimumSample is how many devices there have to be before "everyone
// has it" means anything. On a network of three, two sharing a port is
// not a baseline.
const minimumSample = 8

// riskContext is what the whole scan knows, as opposed to what one
// device knows about itself.
type riskContext struct {
	prevalence map[string]float64 // port -> share of devices with it open
	exposed    map[string]bool    // IP -> has a port mapped to the internet
	devices    int
}

func buildRiskContext(results []deviceResult) riskContext {
	ctx := riskContext{
		prevalence: map[string]float64{},
		exposed:    map[string]bool{},
		devices:    len(results),
	}
	if len(results) == 0 {
		return ctx
	}

	counts := map[string]int{}
	for _, r := range results {
		for _, p := range r.PortNumbers {
			counts[p]++
		}
	}
	for port, n := range counts {
		ctx.prevalence[port] = float64(n) / float64(len(results))
	}

	mappings, _, _ := readUPnPCache()
	for _, m := range mappings {
		ctx.exposed[m.InternalIP] = true
	}
	return ctx
}

// priorityOf ranks one device against the rest of the network.
func priorityOf(r deviceResult, ctx riskContext) (priority, string) {
	if r.Trusted {
		return prioRoutine, "marcado como confiável"
	}
	if len(r.PortNumbers) == 0 {
		return prioRoutine, "nenhuma porta de risco aberta"
	}
	if ctx.exposed[r.IP] {
		return prioAct, "o roteador expõe uma porta deste dispositivo para a internet"
	}
	if r.Risk != "alto" {
		return prioRoutine, "sem serviço de risco alto"
	}

	// which of its high-risk ports are unusual on this network
	var unusual []string
	for _, p := range r.PortNumbers {
		if riskOfPort(p) != "alto" {
			continue
		}
		if ctx.devices >= minimumSample && ctx.prevalence[p] >= ubiquityThreshold {
			continue
		}
		unusual = append(unusual, p)
	}
	if len(unusual) == 0 {
		return prioRoutine, "expõe só o que quase todo aparelho desta rede expõe"
	}
	return prioReview, "porta " + strings.Join(unusual, ", ") + " aberta, incomum nesta rede"
}

// riskOfPort looks the intrinsic classification up in the same table the
// scan uses, so the two can never drift apart.
func riskOfPort(number string) string {
	for _, p := range portsToCheck {
		if p.number == number {
			return p.risk
		}
	}
	return ""
}

// baselinePorts are the ones open on most of the network. Naming them is
// half the value: it tells the reader why so many devices are "alto".
func baselinePorts(ctx riskContext) []string {
	if ctx.devices < minimumSample {
		return nil
	}
	var out []string
	for port, share := range ctx.prevalence {
		if share >= ubiquityThreshold {
			out = append(out, port)
		}
	}
	sort.Slice(out, func(i, j int) bool { return ctx.prevalence[out[i]] > ctx.prevalence[out[j]] })
	return out
}

// priorityBlockHTML explains the ranking, and in particular explains a
// wall of "alto" when that is what the network actually looks like.
func priorityBlockHTML(results []deviceResult, ctx riskContext) string {
	var act, review int
	for _, r := range results {
		switch p, _ := priorityOf(r, ctx); p {
		case prioAct:
			act++
		case prioReview:
			review++
		}
	}

	body := fmt.Sprintf(
		`<div class="meta"><b>%d</b> para agir · <b>%d</b> para revisar · o resto é o padrão desta rede.</div>`,
		act, review)

	if base := baselinePorts(ctx); len(base) > 0 {
		var parts []string
		for _, p := range base {
			service := p
			for _, pc := range portsToCheck {
				if pc.number == p {
					service = fmt.Sprintf("%s (%s)", p, pc.service)
					break
				}
			}
			parts = append(parts, fmt.Sprintf("%s em %.0f%%", html.EscapeString(service), ctx.prevalence[p]*100))
		}
		body += fmt.Sprintf(
			`<div class="meta" style="margin-top:.4rem">Abertas em quase todo aparelho daqui: %s. Continuam sendo risco, mas são a característica do ambiente — não é por elas que se começa.</div>`,
			strings.Join(parts, ", "))
	}

	class := "ok"
	if act > 0 {
		class = "warn"
	}
	return panel(class, "🎯 Por onde começar", body)
}
