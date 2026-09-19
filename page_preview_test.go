package main

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// TestRenderPagePreview validates nothing — it dumps the dashboard to disk
// so the layout can actually be looked at. Run with:
//
//	go test -run TestRenderPagePreview
func TestRenderPagePreview(t *testing.T) {
	if os.Getenv("PREVIEW") == "" {
		t.Skip("defina PREVIEW=1 pra gerar os arquivos de inspeção visual")
	}
	_, ipNet, _ := net.ParseCIDR("192.168.2.0/24")
	network := &networkInfo{
		Interface: "enp0s31f6",
		IP:        net.ParseIP("192.168.2.156").To4(),
		IPNet:     ipNet,
		Gateway:   net.ParseIP("192.168.2.1").To4(),
	}

	tipos := []string{
		"💻 Computador (PC/notebook)", "📱 Celular/tablet", "💡 Dispositivo IoT",
		"🎥 Câmera IP", "🖨️ Impressora", "", "📶 Equipamento de rede (roteador/AP)",
	}

	build := func(n int) []deviceResult {
		var rs []deviceResult
		for i := 0; i < n; i++ {
			r := deviceResult{
				IP:           fmt.Sprintf("192.168.2.%d", i+2),
				Risk:         "alto",
				ProbableType: tipos[i%len(tipos)],
				MAC:          fmt.Sprintf("b0:48:7a:bd:%02x:%02x", i, i*3%255),
				Vendor:       "Intel Corporate",
				ProbableOS:   "🐧 Linux/Android/macOS ou sistema embarcado (TTL 64)",
				Ports: []string{
					"445 (SMB): Compartilhamento de arquivos do Windows — alvo clássico de vírus que se espalham sozinhos pela rede (ex: WannaCry).",
				},
				PortNumbers: []string{"445"},
			}
			switch i % 7 {
			case 0:
				r.Risk = "baixo"
				r.Ports, r.PortNumbers = nil, nil
			case 3:
				r.Risk = "médio"
				r.Ports = []string{"80 (HTTP): Painel web sem criptografia. Dados podem ser interceptados."}
				r.PortNumbers = []string{"80"}
			}
			if i%9 == 0 {
				r.Hostname = fmt.Sprintf("Lab02-%02d.local", i)
			}
			rs = append(rs, r)
		}
		return rs
	}

	for name, devices := range map[string][]deviceResult{
		"pequena": build(9),
		"grande":  build(131),
	} {
		rs := devices
		if len(rs) > 20 {
			// um aparelho com Telnet: a anomalia que a prioridade deve achar
			rs[30].PortNumbers = []string{"445", "23"}
			rs[30].Ports = append(rs[30].Ports, "23 (Telnet): protocolo antigo e inseguro.")
			rs[4].Isolated, rs[4].BlockedPackets, rs[4].IPv4BlockActive = true, 1423, true
			rs[11].Isolated, rs[11].BlockedPackets = true, 87
			rs[6].Trusted = true
		}
		file := "/tmp/preview-" + name + ".html"
		if err := os.WriteFile(file, []byte(pageHTML(network, rs, time.Now().Add(-8*time.Second))), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("gerado %s", file)
	}
}
