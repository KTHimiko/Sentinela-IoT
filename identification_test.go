package main

import (
	"net"
	"testing"
)

func TestIsRandomizedMAC(t *testing.T) {
	cases := []struct {
		name string
		mac  string
		want bool
	}{
		{"MAC de OUI real (Intel)", "3C:97:0E:11:22:33", false},
		{"MAC de OUI real (Apple)", "AC:DE:48:00:11:22", false},
		{"MAC aleatório de privacidade", "DA:A1:19:44:55:66", true},
		{"outro MAC aleatório (2º nibble 6)", "62:00:00:aa:bb:cc", true},
		{"endereço multicast não conta", "01:00:5E:00:00:FB", false},
		{"broadcast não conta", "FF:FF:FF:FF:FF:FF", false},
		{"string curta demais", "A", false},
	}
	for _, c := range cases {
		if got := isRandomizedMAC(c.mac); got != c.want {
			t.Errorf("%s: isRandomizedMAC(%q) = %v, want %v", c.name, c.mac, got, c.want)
		}
	}
}

func TestInferTypeByPorts(t *testing.T) {
	cases := []struct {
		name  string
		ports []string
		want  string
	}{
		{"impressora por 9100", []string{"9100"}, "🖨️ Impressora"},
		{"câmera por 554 tem prioridade", []string{"80", "554"}, "🎥 Câmera IP"},
		{"windows por 445", []string{"445"}, "💻 Computador (provável Windows)"},
		{"windows por 3389", []string{"3389"}, "💻 Computador (provável Windows)"},
		{"banco por 3306", []string{"3306"}, "🗄️ Servidor de banco de dados"},
		{"IoT por telnet", []string{"23"}, "💡 Dispositivo IoT (Telnet aberto — comum em equipamento embarcado)"},
		{"servidor SSH puro", []string{"22"}, "🖥️ Servidor/dispositivo com acesso SSH"},
		{"SSH com web não vira servidor", []string{"22", "80"}, ""},
		{"só web fica sem palpite", []string{"80"}, ""},
		{"sem portas", nil, ""},
	}
	for _, c := range cases {
		if got := inferTypeByPorts(c.ports); got != c.want {
			t.Errorf("%s: inferTypeByPorts(%v) = %q, want %q", c.name, c.ports, got, c.want)
		}
	}
}

func TestKnownDeviceInventory(t *testing.T) {
	knownMu.Lock()
	knownDevices = make(map[string]knownDevice)
	knownMu.Unlock()

	const mac = "AA:BB:CC:DD:EE:FF"
	if alreadyKnown(mac) {
		t.Fatal("a MAC never seen should not be known")
	}
	markSeen(mac, "192.168.0.50")
	if !alreadyKnown(mac) {
		t.Error("a MAC that was seen should become known")
	}
	// case-insensitive: the same MAC in lowercase is the same device
	if !alreadyKnown("aa:bb:cc:dd:ee:ff") {
		t.Error("the lookup should be case-insensitive")
	}
	// an empty MAC is never known and never creates a phantom record
	if alreadyKnown("") {
		t.Error("an empty MAC should not be considered known")
	}
	markSeen("", "192.168.0.51")
	if alreadyKnown("") {
		t.Error("markSeen with an empty MAC should not create a record")
	}
}

func TestDetectDuplicateMAC(t *testing.T) {
	// keep the side effects (history writes) in a temp directory and
	// reset the global state between runs of the test
	t.Chdir(t.TempDir())
	arpDupMu.Lock()
	reportedDuplicateMACs = make(map[string]bool)
	arpDupMu.Unlock()
	historyMu.Lock()
	historyInMemory = nil
	historyMu.Unlock()

	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	network := &networkInfo{
		Gateway:    net.ParseIP("192.168.0.1"),
		GatewayMAC: mac("11:11:11:11:11:11"),
		MAC:        mac("22:22:22:22:22:22"),
	}
	// the same MAC answering for two host IPs is the ARP poisoning signature
	table := map[string]net.HardwareAddr{
		"192.168.0.10": mac("de:ad:be:ef:00:01"),
		"192.168.0.11": mac("de:ad:be:ef:00:01"),
		"192.168.0.12": mac("aa:aa:aa:aa:aa:aa"),
	}
	detectDuplicateMAC(network, table)

	if n := countEvents("alerta_arp_duplicado"); n != 1 {
		t.Fatalf("expected 1 duplicate-MAC alert, got %d", n)
	}
	// calling again with the same pattern must not repeat the alert
	detectDuplicateMAC(network, table)
	if n := countEvents("alerta_arp_duplicado"); n != 1 {
		t.Errorf("the alert should not repeat while the pattern persists (got %d)", n)
	}
}

func countEvents(eventType string) int {
	historyMu.Lock()
	defer historyMu.Unlock()
	n := 0
	for _, e := range historyInMemory {
		if e.Type == eventType {
			n++
		}
	}
	return n
}
