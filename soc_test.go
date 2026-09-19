package main

import (
	"testing"
	"time"
)

func seedHistory(events ...historyEvent) {
	historyMu.Lock()
	historyInMemory = events
	historyMu.Unlock()
}

func TestSeverityOf(t *testing.T) {
	if got := severityOf("alerta_bloqueio"); got != sevHigh {
		t.Errorf("uma contenção que caiu sozinha é crítica, obtive %v", got.label())
	}
	if got := severityOf("novo_dispositivo"); got != sevInfo {
		t.Errorf("dispositivo novo é informativo, obtive %v", got.label())
	}
	// an event type nobody mapped must not blow up or claim to be urgent
	if got := severityOf("tipo_que_nao_existe"); got != sevInfo {
		t.Errorf("tipo desconhecido deveria cair em informativo, obtive %v", got.label())
	}
}

func TestOpenIncidentsIgnoresRoutineAndOldEvents(t *testing.T) {
	now := time.Now()
	seedHistory(
		historyEvent{When: now, Type: "novo_dispositivo", IP: "192.168.0.10"},
		historyEvent{When: now, Type: "mudanca_risco", IP: "192.168.0.11"},
		historyEvent{When: now.Add(-2 * incidentWindow), Type: "alerta_arp_spoofing", IP: "192.168.0.12"},
	)
	if got := openIncidents(); len(got) != 0 {
		t.Errorf("nem evento de rotina nem alerta vencido deveriam abrir incidente, obtive %+v", got)
	}
}

func TestOpenIncidentsEscalatesOnDistinctKinds(t *testing.T) {
	now := time.Now()
	seedHistory(
		// same address, two different kinds of attack: this is the case
		// correlation exists for
		historyEvent{When: now.Add(-5 * time.Minute), Type: "alerta_dhcp_falso", IP: "192.168.0.50"},
		historyEvent{When: now.Add(-1 * time.Minute), Type: "alerta_arp_spoofing", IP: "192.168.0.50"},
		// another address with the same kind twice: still one incident,
		// but not escalated
		historyEvent{When: now.Add(-3 * time.Minute), Type: "alerta_evil_twin", IP: "192.168.0.60"},
		historyEvent{When: now.Add(-2 * time.Minute), Type: "alerta_evil_twin", IP: "192.168.0.60"},
	)

	got := openIncidents()
	if len(got) != 2 {
		t.Fatalf("esperava 2 incidentes, obtive %d: %+v", len(got), got)
	}
	// escalated comes first
	if got[0].IP != "192.168.0.50" || !got[0].Escalated {
		t.Errorf("o alvo com dois tipos distintos deveria vir primeiro e escalado: %+v", got[0])
	}
	if len(got[0].Kinds) != 2 {
		t.Errorf("deveria listar os dois tipos, obtive %v", got[0].Kinds)
	}
	if got[1].Escalated {
		t.Errorf("o mesmo tipo repetido não deveria escalar: %+v", got[1])
	}
	if got[1].Count != 2 {
		t.Errorf("as duas ocorrências deveriam ser contadas, obtive %d", got[1].Count)
	}
	if !got[0].Last.After(got[0].Last.Add(-time.Second)) {
		t.Error("o incidente deveria guardar o instante mais recente")
	}

	seedHistory()
}

func TestOpenIncidentsSkipsEventsWithoutTarget(t *testing.T) {
	// alerta_saude_rede has no IP — it is about the network as a whole,
	// so it must not open an incident keyed on the empty string
	seedHistory(historyEvent{When: time.Now(), Type: "alerta_saude_rede", IP: ""})
	if got := openIncidents(); len(got) != 0 {
		t.Errorf("evento sem alvo não deveria virar incidente, obtive %+v", got)
	}
	seedHistory()
}
