package main

import (
	"testing"
	"time"
)

func resetMetrics() {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	scanSamples, containmentSamples, riskToOrderSamples = nil, nil, nil
	highRiskSince = map[string]time.Time{}
}

func TestSummarize(t *testing.T) {
	if got := summarize(nil); got.Count != 0 {
		t.Errorf("sem amostras deveria dar contagem zero, obtive %+v", got)
	}

	got := summarize([]time.Duration{
		5 * time.Second, time.Second, 3 * time.Second,
	})
	if got.Count != 3 || got.Min != time.Second || got.Max != 5*time.Second || got.Median != 3*time.Second {
		t.Errorf("resumo errado: %+v", got)
	}
	// summarize must not reorder the caller's slice
	original := []time.Duration{3 * time.Second, time.Second}
	summarize(original)
	if original[0] != 3*time.Second {
		t.Error("summarize não deveria reordenar a fatia recebida")
	}
}

func TestSamplesAreCapped(t *testing.T) {
	resetMetrics()
	for i := 0; i < maxSamples+50; i++ {
		recordScanDuration(time.Duration(i) * time.Millisecond)
	}
	scan, _, _ := metricsSnapshot()
	if scan.Count != maxSamples {
		t.Errorf("as amostras deveriam ser limitadas a %d, obtive %d", maxSamples, scan.Count)
	}
	// the cap keeps the most recent ones, so the oldest value is gone
	if scan.Min != 50*time.Millisecond {
		t.Errorf("deveria manter as amostras mais recentes, menor valor ficou %s", scan.Min)
	}
}

func TestNoteRiskLevelTracksOnlyUntrustedHighRisk(t *testing.T) {
	resetMetrics()

	noteRiskLevel([]deviceResult{
		{IP: "192.168.2.10", Risk: "alto"},
		{IP: "192.168.2.11", Risk: "médio"},
		{IP: "192.168.2.12", Risk: "alto", Trusted: true},
	})

	metricsMu.Lock()
	_, alto := highRiskSince["192.168.2.10"]
	_, medio := highRiskSince["192.168.2.11"]
	_, confiavel := highRiskSince["192.168.2.12"]
	marcado := highRiskSince["192.168.2.10"]
	metricsMu.Unlock()

	if !alto {
		t.Error("dispositivo de risco alto deveria ser marcado")
	}
	if medio {
		t.Error("risco médio não deveria ser marcado")
	}
	if confiavel {
		t.Error("dispositivo confiável não deveria ser marcado, mesmo com risco alto")
	}

	// a second scan with the same risk must not reset the clock, or the
	// measured interval would always come out near zero
	time.Sleep(2 * time.Millisecond)
	noteRiskLevel([]deviceResult{{IP: "192.168.2.10", Risk: "alto"}})
	metricsMu.Lock()
	remarcado := highRiskSince["192.168.2.10"]
	metricsMu.Unlock()
	if !remarcado.Equal(marcado) {
		t.Error("o instante da primeira detecção não deveria ser reescrito a cada varredura")
	}
}

func TestNoteRiskLevelClearsWhenRiskDropsOrDeviceLeaves(t *testing.T) {
	resetMetrics()
	noteRiskLevel([]deviceResult{
		{IP: "192.168.2.10", Risk: "alto"},
		{IP: "192.168.2.20", Risk: "alto"},
	})

	// one dropped to low risk, the other vanished from the scan
	noteRiskLevel([]deviceResult{{IP: "192.168.2.10", Risk: "baixo"}})

	metricsMu.Lock()
	defer metricsMu.Unlock()
	if _, ainda := highRiskSince["192.168.2.10"]; ainda {
		t.Error("marca deveria sumir quando o risco baixa")
	}
	if _, ainda := highRiskSince["192.168.2.20"]; ainda {
		t.Error("marca deveria sumir quando o dispositivo sai da rede")
	}
}

func TestRecordContainmentSeparatesHumanTime(t *testing.T) {
	t.Chdir(t.TempDir())
	resetMetrics()
	historyMu.Lock()
	historyInMemory = nil
	historyMu.Unlock()

	// the device has been at high risk for a while before anyone acted
	detected := time.Now().Add(-90 * time.Second)
	metricsMu.Lock()
	highRiskSince["192.168.2.10"] = detected
	metricsMu.Unlock()

	ordered := time.Now()
	recordContainment("192.168.2.10", ordered, ordered.Add(40*time.Millisecond))

	_, containment, riskToOrder := metricsSnapshot()
	if containment.Count != 1 || containment.Median != 40*time.Millisecond {
		t.Errorf("custo da contenção mal registrado: %+v", containment)
	}
	// the 90s of human hesitation must land in the other bucket, not
	// contaminate the artefact's own number
	if riskToOrder.Count != 1 || riskToOrder.Median < 89*time.Second {
		t.Errorf("o tempo até a ordem deveria ficar em separado: %+v", riskToOrder)
	}
	if n := countEvents("metrica_contencao"); n != 1 {
		t.Errorf("esperava 1 evento de métrica no histórico, obtive %d", n)
	}
}

func TestRecordContainmentWithoutPriorDetection(t *testing.T) {
	t.Chdir(t.TempDir())
	resetMetrics()

	ordered := time.Now()
	recordContainment("192.168.2.99", ordered, ordered.Add(10*time.Millisecond))

	_, containment, riskToOrder := metricsSnapshot()
	if containment.Count != 1 {
		t.Error("a contenção deveria ser medida mesmo sem detecção prévia de risco")
	}
	// isolating a device that was never flagged has no interval to report
	if riskToOrder.Count != 0 {
		t.Errorf("sem detecção prévia não há intervalo a medir, obtive %+v", riskToOrder)
	}
}

func TestFormatDuration(t *testing.T) {
	cases := map[time.Duration]string{
		40 * time.Millisecond:   "40 ms",
		1500 * time.Millisecond: "1.5 s",
		90 * time.Second:        "1.5 min",
		3 * time.Hour:           "3.0 h",
	}
	for d, want := range cases {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
