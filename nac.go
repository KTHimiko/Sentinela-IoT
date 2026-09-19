package main

import (
	"fmt"
	"html"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- admission policy ----------

// The inventory of known devices already existed, but only to quieten
// repeated "new device" alerts. A NAC decides with it: a known device
// gets in, an unknown one does not. Wiring the inventory into a verdict
// is what turns the artefact from something that reports into something
// that controls access — the promise the category name makes.
//
// Three modes, from POLITICA_NAC:
//
//	off       (default) no verdict is acted on; the dashboard still shows it
//	simular   the verdict is recorded in the history, nothing is blocked
//	aplicar   the verdict is enforced: a denied device is isolated
//
// Default off, and "simular" exists because turning this on blind is how
// you cut off the household television. Run it in simulation for a week,
// read the history, then decide.
const (
	policyOff      = "off"
	policySimulate = "simular"
	policyEnforce  = "aplicar"
)

// learningWindow is the grace period after startup during which nothing
// is ever denied. On a first run every device is unknown, so enforcing
// immediately would quarantine the whole network; this window lets the
// inventory fill from what is already there. It mirrors what the rogue
// DHCP detector does to learn the legitimate servers.
var learningWindow = 10 * time.Minute

var policyMu sync.RWMutex
var policyMode = policyOff
var policyStartedAt time.Time

// policyDuration is how long an automatically denied device stays
// isolated. Deliberately short: a wrong automatic decision should expire
// on its own, not wait for someone to notice.
var policyDuration = 15 * time.Minute

type verdict struct {
	Allowed bool
	Reason  string
}

func configurePolicy() string {
	policyMu.Lock()
	defer policyMu.Unlock()

	switch strings.ToLower(strings.TrimSpace(os.Getenv("POLITICA_NAC"))) {
	case policySimulate:
		policyMode = policySimulate
	case policyEnforce:
		policyMode = policyEnforce
	default:
		policyMode = policyOff
	}
	if v := os.Getenv("POLITICA_APRENDIZADO_MINUTOS"); v != "" {
		if m, err := strconv.Atoi(v); err == nil && m >= 0 {
			learningWindow = time.Duration(m) * time.Minute
		}
	}
	policyStartedAt = time.Now()
	return policyMode
}

func currentPolicy() (mode string, learning bool) {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return policyMode, time.Since(policyStartedAt) < learningWindow
}

// evaluateAdmission is the policy itself, and it is intentionally small:
// a rule nobody can state in one sentence is a rule nobody can audit.
func evaluateAdmission(r deviceResult) verdict {
	switch {
	case r.Trusted:
		return verdict{true, "marcado como confiável"}
	case r.Agent != "":
		// another agent owns this subnet and runs its own policy there
		return verdict{true, "sob a política do agente " + r.Agent}
	case r.OutsideSubnet:
		return verdict{true, "fora da sub-rede — sem alcance para aplicar política"}
	case r.MAC == "":
		return verdict{true, "sem MAC resolvido — indeterminado"}
	case !alreadyKnown(r.MAC):
		return verdict{false, "dispositivo desconhecido: primeiro MAC visto nesta rede"}
	case r.Risk == "alto":
		return verdict{false, "expõe serviço classificado como risco alto"}
	default:
		return verdict{true, "conhecido e sem serviço de risco alto"}
	}
}

// applyPolicy runs after each scan. It is the only place that can isolate
// without someone clicking, so it is also the place that has to be most
// conservative: nothing happens while learning, nothing happens in the
// modes that are not "aplicar", and an already isolated device is left
// alone.
func applyPolicy(network *networkInfo, results []deviceResult) {
	mode, learning := currentPolicy()
	if mode == policyOff || learning {
		return
	}

	for _, r := range results {
		if r.Isolated || r.Agent != "" {
			continue
		}
		v := evaluateAdmission(r)
		if v.Allowed {
			continue
		}

		if mode == policySimulate {
			recordEvent("nac_simulado", r.IP, fmt.Sprintf(
				"A política de admissão TERIA isolado este dispositivo: %s. Nada foi bloqueado — o modo é simulação.", v.Reason))
			continue
		}

		if err := isolateByIP(network, r.IP, policyDuration); err != nil {
			recordEvent("nac_falhou", r.IP, fmt.Sprintf(
				"A política de admissão decidiu isolar (%s), mas não consegui: %v", v.Reason, err))
			continue
		}
		recordEvent("nac_negado", r.IP, fmt.Sprintf(
			"Isolado automaticamente pela política de admissão: %s. Reconecta sozinho em %s.", v.Reason, policyDuration))
	}
}

// startPolicy hooks the evaluation onto the scan loop.
func startPolicy(network *networkInfo, interval time.Duration) {
	mode, _ := currentPolicy()
	if mode == policyOff {
		return
	}
	go func() {
		for {
			time.Sleep(interval)
			results, _ := readCache()
			applyPolicy(network, results)
		}
	}()
}

// nacBlockHTML shows what the policy is doing, and — when it is off or
// simulating — what it would do. Showing the verdict even with the policy
// disabled is the point: it is how someone decides whether to turn it on.
func nacBlockHTML(results []deviceResult) string {
	mode, learning := currentPolicy()

	var denied []deviceResult
	for _, r := range results {
		if !evaluateAdmission(r).Allowed {
			denied = append(denied, r)
		}
	}

	state := ""
	class := ""
	switch {
	case mode == policyOff:
		state = "Política <b>desligada</b> — os veredictos abaixo são só informativos. Ligue com POLITICA_NAC=simular."
	case learning:
		state = fmt.Sprintf("Em <b>aprendizado</b> por mais %s — nada é bloqueado enquanto o inventário se forma.",
			formatDuration(time.Until(policyStartedAt.Add(learningWindow))))
	case mode == policySimulate:
		state = "Modo <b>simulação</b> — as decisões vão para o histórico, nada é bloqueado."
	default:
		state = fmt.Sprintf("Modo <b>aplicar</b> — dispositivos negados são isolados por %s automaticamente.", policyDuration)
		class = "warn"
	}

	body := fmt.Sprintf(`<div class="meta">%s</div>`, state)
	if len(denied) == 0 {
		body += `<div class="meta" style="margin-top:.4rem">Nenhum dispositivo reprovado agora.</div>`
		if class == "" {
			class = "ok"
		}
		return panel(class, "🚦 Política de admissão (NAC)", body)
	}

	// On a fresh inventory every device is unknown, so this list can be
	// the whole network. Printing one line each buried the rest of the
	// dashboard, so it is grouped by reason with only a few examples —
	// the count is the information, the addresses are the illustration.
	const examplesPerReason = 4
	order := []string{}
	byReason := map[string][]string{}
	for _, r := range denied {
		reason := evaluateAdmission(r).Reason
		if _, seen := byReason[reason]; !seen {
			order = append(order, reason)
		}
		byReason[reason] = append(byReason[reason], r.IP)
	}

	var lines strings.Builder
	for _, reason := range order {
		ips := byReason[reason]
		shown := ips
		if len(shown) > examplesPerReason {
			shown = shown[:examplesPerReason]
		}
		extra := ""
		if rest := len(ips) - len(shown); rest > 0 {
			extra = fmt.Sprintf(" e mais %d", rest)
		}
		lines.WriteString(fmt.Sprintf("<li><b>%d</b> — %s <span class=\"mac\">(%s%s)</span></li>",
			len(ips), html.EscapeString(reason),
			html.EscapeString(strings.Join(shown, ", ")), extra))
	}
	body += fmt.Sprintf(`<div class="meta" style="margin-top:.4rem">%d dispositivo(s) reprovado(s):</div><ul>%s</ul>`,
		len(denied), lines.String())
	return panel("warn", "🚦 Política de admissão (NAC)", body)
}
