package main

import (
	"testing"
	"time"
)

func resetHealth() {
	healthMu.Lock()
	hostHealthByIP = map[string]*hostHealth{}
	healthMu.Unlock()
}

func TestRecordProbeIgnoresHostsThatNeverAnswered(t *testing.T) {
	resetHealth()
	// an empty /24 produces 250-odd misses per cycle; tracking them would
	// bury the real devices
	for i := 0; i < 10; i++ {
		recordProbe("192.168.0.99", 0, false)
	}
	if _, _, ok := healthOf("192.168.0.99"); ok {
		t.Error("host que nunca respondeu não deveria entrar no inventário de saúde")
	}

	// once it answers, later absences do count
	recordProbe("192.168.0.99", 5*time.Millisecond, true)
	recordProbe("192.168.0.99", 0, false)
	_, availability, ok := healthOf("192.168.0.99")
	if !ok {
		t.Fatal("depois de responder uma vez, deveria ser rastreado")
	}
	if availability != 0.5 {
		t.Errorf("1 resposta em 2 ciclos = 50%%, obtive %.2f", availability)
	}
}

func TestHealthOfReportsMedian(t *testing.T) {
	resetHealth()
	for _, ms := range []int{10, 2, 6} {
		recordProbe("192.168.0.10", time.Duration(ms)*time.Millisecond, true)
	}
	median, availability, ok := healthOf("192.168.0.10")
	if !ok {
		t.Fatal("deveria ter medição")
	}
	if median != 6*time.Millisecond {
		t.Errorf("mediana de 2/6/10 é 6ms, obtive %s", median)
	}
	if availability != 1 {
		t.Errorf("sem falhas a disponibilidade é 100%%, obtive %.2f", availability)
	}
}

func TestProbeSamplesAreCapped(t *testing.T) {
	resetHealth()
	for i := 0; i < maxProbeSamples+30; i++ {
		recordProbe("192.168.0.11", time.Millisecond, true)
	}
	healthMu.Lock()
	n := len(hostHealthByIP["192.168.0.11"].rtts)
	healthMu.Unlock()
	if n != maxProbeSamples {
		t.Errorf("amostras deveriam ser limitadas a %d, obtive %d", maxProbeSamples, n)
	}
}

func TestFlakiestHostsRanksWorstFirst(t *testing.T) {
	resetHealth()
	// steady: answers every cycle
	for i := 0; i < 10; i++ {
		recordProbe("192.168.0.20", 3*time.Millisecond, true)
	}
	// flaky: half the cycles
	for i := 0; i < 10; i++ {
		recordProbe("192.168.0.21", 3*time.Millisecond, i%2 == 0)
	}
	// worse: answered once, then vanished
	recordProbe("192.168.0.22", 3*time.Millisecond, true)
	for i := 0; i < 9; i++ {
		recordProbe("192.168.0.22", 0, false)
	}
	// too few cycles to judge
	recordProbe("192.168.0.23", 3*time.Millisecond, true)
	recordProbe("192.168.0.23", 0, false)

	got := flakiestHosts(5)
	if len(got) != 2 {
		t.Fatalf("esperava só os dois com histórico suficiente e falhas, obtive %+v", got)
	}
	if got[0].IP != "192.168.0.22" {
		t.Errorf("o pior deveria vir primeiro, obtive %s", got[0].IP)
	}
	for _, g := range got {
		if g.IP == "192.168.0.20" {
			t.Error("host sem falha nenhuma não deveria aparecer na lista")
		}
		if g.IP == "192.168.0.23" {
			t.Error("host com poucos ciclos não deveria ser julgado ainda")
		}
	}
}

func TestExtractRTT(t *testing.T) {
	saida := `PING 192.168.0.1 (192.168.0.1) 56(84) bytes of data.
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=3.45 ms
64 bytes from 192.168.0.1: icmp_seq=2 ttl=64 time=9.90 ms`
	if got := extractRTT(saida); got != 3450*time.Microsecond {
		t.Errorf("deveria ler o primeiro time=, obtive %s", got)
	}
	if got := extractRTT("sem tempo nenhum aqui"); got != 0 {
		t.Errorf("saída sem tempo deveria dar zero, obtive %s", got)
	}
}
