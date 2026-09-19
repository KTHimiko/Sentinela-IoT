package main

import (
	"fmt"
	"testing"
	"time"
)

// windowsLab mirrors the situation that motivated all this: a room full
// of machines that all have SMB open, so "alto" stops sorting anything.
func windowsLab(n int) []deviceResult {
	var rs []deviceResult
	for i := 0; i < n; i++ {
		rs = append(rs, deviceResult{
			IP:          fmt.Sprintf("192.168.2.%d", i+2),
			MAC:         fmt.Sprintf("aa:bb:cc:00:00:%02x", i),
			Risk:        "alto",
			PortNumbers: []string{"445"},
		})
	}
	return rs
}

func TestUbiquitousPortDropsToRoutine(t *testing.T) {
	upnpMu.Lock()
	upnpMappings = nil
	upnpMu.Unlock()

	devices := windowsLab(20)
	ctx := buildRiskContext(devices)

	if got := ctx.prevalence["445"]; got != 1 {
		t.Fatalf("445 deveria estar em 100%% dos aparelhos, obtive %.2f", got)
	}
	// still classified "alto" — the intrinsic risk is untouched
	if devices[0].Risk != "alto" {
		t.Error("a classificação de risco não deveria mudar")
	}
	// but it is the environment's baseline, not where to start
	p, reason := priorityOf(devices[0], ctx)
	if p != prioRoutine {
		t.Errorf("porta onipresente deveria virar rotina, obtive %s (%s)", p.label(), reason)
	}
	if base := baselinePorts(ctx); len(base) != 1 || base[0] != "445" {
		t.Errorf("445 deveria ser listada como característica do ambiente, obtive %v", base)
	}
}

func TestUnusualPortStandsOut(t *testing.T) {
	upnpMu.Lock()
	upnpMappings = nil
	upnpMu.Unlock()

	devices := windowsLab(20)
	// one machine also has Telnet open — that is the anomaly
	devices[7].PortNumbers = []string{"445", "23"}
	ctx := buildRiskContext(devices)

	p, reason := priorityOf(devices[7], ctx)
	if p != prioReview {
		t.Errorf("a porta incomum deveria destacar o aparelho, obtive %s", p.label())
	}
	if reason == "" {
		t.Error("o motivo deveria nomear a porta incomum")
	}
	// the others stay routine
	if p, _ := priorityOf(devices[0], ctx); p != prioRoutine {
		t.Errorf("os demais continuam rotina, obtive %s", p.label())
	}
}

func TestInternetExposureOutranksEverything(t *testing.T) {
	devices := windowsLab(20)
	upnpMu.Lock()
	upnpMappings = []upnpMapping{{InternalIP: "192.168.2.5", ExternalPort: "445", Protocol: "TCP"}}
	upnpLastCheck = time.Now()
	upnpMu.Unlock()
	defer func() {
		upnpMu.Lock()
		upnpMappings = nil
		upnpMu.Unlock()
	}()

	ctx := buildRiskContext(devices)
	// same ubiquitous port as everyone else, but this one is reachable
	// from outside — a difference in kind, not in degree
	p, _ := priorityOf(deviceResult{IP: "192.168.2.5", Risk: "alto", PortNumbers: []string{"445"}}, ctx)
	if p != prioAct {
		t.Errorf("exposição à internet deveria ser a prioridade máxima, obtive %s", p.label())
	}
}

func TestSmallNetworkHasNoBaseline(t *testing.T) {
	upnpMu.Lock()
	upnpMappings = nil
	upnpMu.Unlock()

	// three devices sharing a port is not an environment characteristic
	devices := windowsLab(3)
	ctx := buildRiskContext(devices)
	if base := baselinePorts(ctx); len(base) != 0 {
		t.Errorf("amostra pequena não deveria produzir baseline, obtive %v", base)
	}
	if p, _ := priorityOf(devices[0], ctx); p != prioReview {
		t.Errorf("sem baseline, risco alto continua a revisar, obtive %s", p.label())
	}
}

func TestTrustedAndCleanDevicesAreRoutine(t *testing.T) {
	ctx := buildRiskContext(windowsLab(20))
	if p, _ := priorityOf(deviceResult{Risk: "alto", PortNumbers: []string{"23"}, Trusted: true}, ctx); p != prioRoutine {
		t.Error("confiável deveria ficar em rotina mesmo com porta incomum")
	}
	if p, _ := priorityOf(deviceResult{Risk: "baixo"}, ctx); p != prioRoutine {
		t.Error("sem porta aberta deveria ficar em rotina")
	}
}

func TestRiskOfPortMatchesTheScanTable(t *testing.T) {
	if got := riskOfPort("23"); got != "alto" {
		t.Errorf("Telnet é alto na tabela da varredura, obtive %q", got)
	}
	if got := riskOfPort("443"); got != "baixo" {
		t.Errorf("HTTPS é baixo na tabela da varredura, obtive %q", got)
	}
	if got := riskOfPort("9999"); got != "" {
		t.Errorf("porta fora da tabela deveria devolver vazio, obtive %q", got)
	}
}
