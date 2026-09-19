package main

import (
	"net"
	"testing"
)

func TestMacAleatorio(t *testing.T) {
	casos := []struct {
		nome string
		mac  string
		quer bool
	}{
		{"MAC de OUI real (Intel)", "3C:97:0E:11:22:33", false},
		{"MAC de OUI real (Apple)", "AC:DE:48:00:11:22", false},
		{"MAC aleatório de privacidade", "DA:A1:19:44:55:66", true},
		{"outro MAC aleatório (2º nibble 6)", "62:00:00:aa:bb:cc", true},
		{"endereço multicast não conta", "01:00:5E:00:00:FB", false},
		{"broadcast não conta", "FF:FF:FF:FF:FF:FF", false},
		{"string curta demais", "A", false},
	}
	for _, c := range casos {
		if got := macAleatorio(c.mac); got != c.quer {
			t.Errorf("%s: macAleatorio(%q) = %v, queria %v", c.nome, c.mac, got, c.quer)
		}
	}
}

func TestInferirTipoPorPortas(t *testing.T) {
	casos := []struct {
		nome   string
		portas []string
		quer   string
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
	for _, c := range casos {
		if got := inferirTipoPorPortas(c.portas); got != c.quer {
			t.Errorf("%s: inferirTipoPorPortas(%v) = %q, queria %q", c.nome, c.portas, got, c.quer)
		}
	}
}

func TestInventarioConhecidos(t *testing.T) {
	conhecidosMu.Lock()
	conhecidos = make(map[string]dispositivoConhecido)
	conhecidosMu.Unlock()

	const mac = "AA:BB:CC:DD:EE:FF"
	if jaConhecido(mac) {
		t.Fatal("MAC nunca visto não deveria ser conhecido")
	}
	marcarVisto(mac, "192.168.0.50")
	if !jaConhecido(mac) {
		t.Error("MAC visto deveria passar a ser conhecido")
	}
	// case-insensitive: o mesmo MAC em minúsculas é o mesmo dispositivo
	if !jaConhecido("aa:bb:cc:dd:ee:ff") {
		t.Error("a consulta deveria ser insensível a maiúsculas/minúsculas")
	}
	// MAC vazio nunca é conhecido nem cria registro fantasma
	if jaConhecido("") {
		t.Error("MAC vazio não deveria ser considerado conhecido")
	}
	marcarVisto("", "192.168.0.51")
	if jaConhecido("") {
		t.Error("marcarVisto com MAC vazio não deveria criar registro")
	}
}

func TestDetectarMACDuplicado(t *testing.T) {
	// isola os efeitos colaterais (gravação de histórico) num diretório
	// temporário e zera o estado global entre execuções do teste.
	t.Chdir(t.TempDir())
	arpDupMu.Lock()
	arpDuplicadosReportados = make(map[string]bool)
	arpDupMu.Unlock()
	historicoMu.Lock()
	historicoMem = nil
	historicoMu.Unlock()

	mac := func(s string) net.HardwareAddr { m, _ := net.ParseMAC(s); return m }
	rede := &infoRede{
		Gateway:    net.ParseIP("192.168.0.1"),
		GatewayMAC: mac("11:11:11:11:11:11"),
		MAC:        mac("22:22:22:22:22:22"),
	}
	// o mesmo MAC responde por dois IPs de host = assinatura de ARP poisoning
	tabela := map[string]net.HardwareAddr{
		"192.168.0.10": mac("de:ad:be:ef:00:01"),
		"192.168.0.11": mac("de:ad:be:ef:00:01"),
		"192.168.0.12": mac("aa:aa:aa:aa:aa:aa"),
	}
	detectarMACDuplicado(rede, tabela)

	if n := contarEventos("alerta_arp_duplicado"); n != 1 {
		t.Fatalf("esperava 1 alerta de MAC duplicado, obtive %d", n)
	}
	// chamar de novo com o mesmo padrão não deve repetir o alerta
	detectarMACDuplicado(rede, tabela)
	if n := contarEventos("alerta_arp_duplicado"); n != 1 {
		t.Errorf("o alerta não deveria repetir enquanto o padrão persiste (obtive %d)", n)
	}
}

func contarEventos(tipo string) int {
	historicoMu.Lock()
	defer historicoMu.Unlock()
	n := 0
	for _, e := range historicoMem {
		if e.Tipo == tipo {
			n++
		}
	}
	return n
}
