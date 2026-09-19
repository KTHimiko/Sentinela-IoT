package main

import (
	"testing"
	"time"
)

func withKnown(macs ...string) {
	knownMu.Lock()
	knownDevices = map[string]knownDevice{}
	knownMu.Unlock()
	for _, m := range macs {
		markSeen(m, "192.168.0.1")
	}
}

func TestEvaluateAdmission(t *testing.T) {
	withKnown("AA:AA:AA:AA:AA:AA")

	cases := []struct {
		name    string
		device  deviceResult
		allowed bool
	}{
		{"conhecido e sem risco alto", deviceResult{MAC: "AA:AA:AA:AA:AA:AA", Risk: "baixo"}, true},
		{"conhecido mas com risco alto", deviceResult{MAC: "AA:AA:AA:AA:AA:AA", Risk: "alto"}, false},
		{"desconhecido", deviceResult{MAC: "BB:BB:BB:BB:BB:BB", Risk: "baixo"}, false},
		// the trust list is the manual override and wins over everything
		{"confiável vence o risco alto", deviceResult{MAC: "CC:CC:CC:CC:CC:CC", Risk: "alto", Trusted: true}, true},
		// no MAC means we cannot even identify it, let alone contain it
		{"sem MAC resolvido", deviceResult{MAC: "", Risk: "alto"}, true},
		// out of reach: denying would be a decision we cannot enforce
		{"fora da sub-rede", deviceResult{MAC: "DD:DD:DD:DD:DD:DD", Risk: "alto", OutsideSubnet: true}, true},
		{"sob outro agente", deviceResult{MAC: "EE:EE:EE:EE:EE:EE", Risk: "alto", Agent: "andar1"}, true},
	}
	for _, c := range cases {
		if got := evaluateAdmission(c.device); got.Allowed != c.allowed {
			t.Errorf("%s: permitido=%v, queria %v (motivo: %s)", c.name, got.Allowed, c.allowed, got.Reason)
		}
	}
}

func TestPolicyDefaultsToOff(t *testing.T) {
	t.Setenv("POLITICA_NAC", "")
	if got := configurePolicy(); got != policyOff {
		t.Errorf("sem configuração a política deveria ficar desligada, obtive %q", got)
	}
	t.Setenv("POLITICA_NAC", "qualquer coisa")
	if got := configurePolicy(); got != policyOff {
		t.Errorf("valor inválido deveria cair pra desligada, obtive %q", got)
	}
	t.Setenv("POLITICA_NAC", "APLICAR")
	if got := configurePolicy(); got != policyEnforce {
		t.Errorf("o modo deveria ser insensível a maiúsculas, obtive %q", got)
	}
}

// The learning window is the guard that keeps a first run from
// quarantining the whole house: on a fresh inventory every device is
// unknown, so enforcement has to wait for the baseline to form.
func TestPolicyNeverActsWhileLearning(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("POLITICA_NAC", "aplicar")
	t.Setenv("POLITICA_APRENDIZADO_MINUTOS", "10")
	configurePolicy()
	withKnown()
	historyMu.Lock()
	historyInMemory = nil
	historyMu.Unlock()

	_, learning := currentPolicy()
	if !learning {
		t.Fatal("logo após iniciar deveria estar em aprendizado")
	}

	// an unknown device that the policy would otherwise isolate
	applyPolicy(nil, []deviceResult{{IP: "192.168.0.77", MAC: "FF:FF:FF:FF:FF:FF", Risk: "alto"}})

	if n := countEvents("nac_negado"); n != 0 {
		t.Errorf("nada deveria ser isolado durante o aprendizado, obtive %d", n)
	}
	if n := countEvents("nac_simulado"); n != 0 {
		t.Errorf("nem simulação durante o aprendizado, obtive %d", n)
	}
}

func TestPolicySimulateRecordsWithoutBlocking(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("POLITICA_NAC", "simular")
	t.Setenv("POLITICA_APRENDIZADO_MINUTOS", "0") // sem aprendizado, avalia já
	configurePolicy()
	withKnown("AA:AA:AA:AA:AA:AA")
	historyMu.Lock()
	historyInMemory = nil
	historyMu.Unlock()

	// network is nil on purpose: in simulation nothing may touch it, and
	// a nil dereference here would prove the opposite
	applyPolicy(nil, []deviceResult{
		{IP: "192.168.0.10", MAC: "AA:AA:AA:AA:AA:AA", Risk: "baixo"}, // passa
		{IP: "192.168.0.77", MAC: "FF:FF:FF:FF:FF:FF", Risk: "baixo"}, // desconhecido
	})

	if n := countEvents("nac_simulado"); n != 1 {
		t.Errorf("esperava 1 decisão simulada, obtive %d", n)
	}
	if n := countEvents("nac_negado"); n != 0 {
		t.Errorf("simulação não pode isolar nada, obtive %d", n)
	}
}

func TestPolicySkipsAlreadyIsolated(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("POLITICA_NAC", "simular")
	t.Setenv("POLITICA_APRENDIZADO_MINUTOS", "0")
	configurePolicy()
	withKnown()
	historyMu.Lock()
	historyInMemory = nil
	historyMu.Unlock()

	applyPolicy(nil, []deviceResult{
		{IP: "192.168.0.77", MAC: "FF:FF:FF:FF:FF:FF", Risk: "alto", Isolated: true},
	})
	if n := countEvents("nac_simulado"); n != 0 {
		t.Errorf("quem já está isolado não deveria ser reavaliado, obtive %d", n)
	}
}

func TestLearningWindowIsConfigurable(t *testing.T) {
	t.Setenv("POLITICA_NAC", "simular")
	t.Setenv("POLITICA_APRENDIZADO_MINUTOS", "45")
	configurePolicy()
	if learningWindow != 45*time.Minute {
		t.Errorf("janela de aprendizado deveria ser 45min, obtive %s", learningWindow)
	}
}
