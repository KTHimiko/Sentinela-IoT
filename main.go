package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

type portInfo struct {
	number      string
	service     string
	risk        string
	explanation string
}

// The risk keys ("baixo"/"médio"/"alto") and the explanations stay in
// Portuguese: they are data the user reads in the dashboard, not
// identifiers.
var portsToCheck = []portInfo{
	{"21", "FTP", "alto", "Transferência de arquivos antiga e sem criptografia — usuário e senha trafegam visíveis pra quem estiver espiando a rede."},
	{"22", "SSH", "médio", "Acesso remoto ao dispositivo. Se a senha for fraca, pode ser invadido."},
	{"23", "Telnet", "alto", "Um protocolo antigo e inseguro — qualquer pessoa na internet pode tentar acessar esse dispositivo."},
	{"25", "SMTP", "médio", "Serviço de e-mail exposto — se mal configurado, golpistas podem usá-lo pra mandar spam em nome da sua rede."},
	{"80", "HTTP", "médio", "Painel web sem criptografia. Dados podem ser interceptados."},
	{"110", "POP3", "médio", "E-mail antigo sem criptografia — mensagens e senha podem ser interceptadas."},
	{"143", "IMAP", "médio", "E-mail sem criptografia — mensagens e senha podem ser interceptadas."},
	{"443", "HTTPS", "baixo", "Painel web com criptografia — mais seguro que o normal."},
	{"445", "SMB", "alto", "Compartilhamento de arquivos do Windows — alvo clássico de vírus que se espalham sozinhos pela rede (ex: WannaCry)."},
	{"554", "RTSP", "médio", "Transmissão de vídeo, comum em câmeras IP — se não tiver senha, qualquer um na rede pode assistir."},
	{"3306", "MySQL", "alto", "Banco de dados exposto na rede — sem senha forte, os dados podem ser roubados ou apagados."},
	{"3389", "RDP", "alto", "Acesso remoto de área de trabalho — alvo clássico de ataques automatizados."},
	{"5432", "PostgreSQL", "alto", "Banco de dados exposto na rede — mesmo risco de um MySQL exposto."},
	{"5900", "VNC", "alto", "Acesso remoto à tela do dispositivo — em muitos casos configurado sem senha nenhuma."},
	{"8080", "HTTP alternativo", "médio", "Painel de administração alternativo (comum em roteadores e câmeras), sem criptografia."},
	{"8443", "HTTPS alternativo", "baixo", "Versão criptografada da porta 8080."},
	{"9100", "Impressora de rede", "médio", "Porta de impressão em rede exposta — alguém de fora pode mandar imprimir ou ver documentos na fila."},
}

var riskLevel = map[string]int{"baixo": 1, "médio": 2, "alto": 3}
var riskColor = map[string]string{"baixo": "#2e7d32", "médio": "#b8860b", "alto": "#b3261e"}
var riskLabel = map[string]string{"baixo": "🟢 Baixo risco", "médio": "🟡 Risco médio", "alto": "🔴 Risco alto"}

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("⚠️  Isolamento por ARP spoofing exige acesso a raw sockets.")
		fmt.Println("   Rode com: sudo go run .")
		fmt.Println("   (ou: sudo setcap cap_net_raw,cap_net_admin=eip ./immunegate)")
	}

	network, err := detectNetwork()
	if err != nil {
		fmt.Println("Erro ao detectar a rede local:", err)
		os.Exit(1)
	}
	fmt.Printf("Rede detectada: %s via interface %s (gateway %s, MAC %s)\n",
		network.IPNet.String(), network.Interface, network.Gateway, network.GatewayMAC)

	if v := os.Getenv("REDES_EXTRAS"); v != "" {
		network.ExtraNetworks = parseExtraNetworks(v)
		for _, extra := range network.ExtraNetworks {
			fmt.Printf("Varrendo também %s (outra sub-rede: dá pra detectar, mas não pra identificar por MAC nem isolar)\n", extra)
		}
	}

	loadHistory()
	loadTrusted()
	loadKnownDevices()
	cleanOrphanRules(network)
	startIsolationTimeoutWatcher(network)
	startRogueDHCPDetection(network.Interface)

	interval := 20 * time.Second
	if v := os.Getenv("INTERVALO_SEGUNDOS"); v != "" {
		if seconds, err := strconv.Atoi(v); err == nil && seconds > 0 {
			interval = time.Duration(seconds) * time.Second
		}
	}
	fmt.Printf("Monitoramento contínuo a cada %s\n", interval)
	startContinuousMonitoring(network, interval)
	startUPnPCheck()
	startMDNSListener(network.Interface)
	startSSDPProbe()
	startWifiCheck()

	switch policy := configurePolicy(); policy {
	case policySimulate:
		fmt.Printf("Política de admissão em simulação: decisões vão pro histórico, nada é bloqueado (aprendizado de %s)\n", learningWindow)
	case policyEnforce:
		fmt.Printf("Política de admissão ATIVA: desconhecidos e risco alto serão isolados por %s (aprendizado de %s)\n", policyDuration, learningWindow)
	}
	startPolicy(network, interval)

	mode, agents := configureDistributedMode()
	if mode == modeCentral && len(agents) > 0 {
		for _, a := range agents {
			fmt.Printf("Central: agregando o agente %s (%s)\n", a.Name, a.URL)
		}
		startAgentPolling(agents, interval)
	}

	// the route paths stay in Portuguese, like the rest of the interface
	http.HandleFunc("/", handler(network))
	http.HandleFunc("/atualizar", refreshHandler(network))
	http.HandleFunc("/historico", historyHandler)
	http.HandleFunc("/mapa", mapHandler(network))
	http.HandleFunc("/isolar", isolateHandler(network))
	http.HandleFunc("/reconectar", reconnectHandler(network))
	http.HandleFunc("/confiavel", trustHandler(network))

	port := "8090"
	if v := os.Getenv("PORTA"); v != "" {
		if _, err := strconv.Atoi(v); err == nil {
			port = v
		}
	}

	// The dashboard is bound to localhost: it has no authentication of its
	// own — it was written for someone sitting at the machine — so making
	// its port reachable would hand the "isolate" button to anyone on the
	// LAN. PAINEL_NA_REDE opts out, for showing it on another screen, and
	// is refused in agent mode, where only the token-protected API should
	// be on the network.
	dashboardAddr := "127.0.0.1:" + port
	if os.Getenv("PAINEL_NA_REDE") == "1" && mode != modeAgent {
		dashboardAddr = ":" + port
		fmt.Println("⚠️  PAINEL_NA_REDE=1: o painel está aberto pra rede inteira, sem senha — qualquer um nela pode isolar dispositivos.")
	}
	if mode == modeAgent {

		apiPort := defaultAPIPort
		if v := os.Getenv("PORTA_API"); v != "" {
			if _, err := strconv.Atoi(v); err == nil {
				apiPort = v
			}
		}
		agentName := os.Getenv("NOME_AGENTE")
		if agentName == "" {
			agentName, _ = os.Hostname()
		}
		mux := registerAgentAPI(network, agentName)
		go func() {
			fmt.Printf("Agente %q: API em http://0.0.0.0:%s (protegida por IMMUNEGATE_TOKEN)\n", agentName, apiPort)
			if err := http.ListenAndServe(":"+apiPort, mux); err != nil {
				fmt.Println("API do agente caiu:", err)
			}
		}()
	}

	// bind first, announce second: ListenAndServe would have swallowed the
	// error and let main return with status 0, so a port already taken by
	// another instance looked exactly like a clean start that then quit
	listener, err := net.Listen("tcp", dashboardAddr)
	if err != nil {
		fmt.Printf("Não consegui abrir a porta %s: %v\n", port, err)
		// sudo matters here: the socket belongs to a root process, and
		// without it ss prints the line with no owner, which is the least
		// useful half of the answer
		fmt.Printf("   Provavelmente já há outra instância rodando. Veja qual com: sudo ss -tlnp | grep %s\n", port)
		fmt.Println("   Pra derrubar a anterior: sudo pkill -f immunegate")
		os.Exit(1)
	}
	fmt.Printf("Dashboard rodando em http://localhost:%s\n", port)
	if err := http.Serve(listener, dashboardGuard(http.DefaultServeMux)); err != nil {
		fmt.Println("O dashboard parou:", err)
		os.Exit(1)
	}
}
