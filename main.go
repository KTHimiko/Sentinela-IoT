package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

type portInfo struct {
	number     string
	service    string
	risk       string
	explicacao string
}

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
		fmt.Println("   (ou: sudo setcap cap_net_raw,cap_net_admin=eip ./sentinela-iot)")
	}

	rede, err := detectarRede()
	if err != nil {
		fmt.Println("Erro ao detectar a rede local:", err)
		os.Exit(1)
	}
	fmt.Printf("Rede detectada: %s via interface %s (gateway %s, MAC %s)\n",
		rede.IPNet.String(), rede.Interface, rede.Gateway, rede.GatewayMAC)

	carregarHistorico()
	carregarConfiaveis()
	limparRegrasOrfas(rede)
	iniciarVigiaTimeoutIsolamento(rede)
	iniciarDeteccaoDHCPFalso(rede.Interface)
	iniciarPortalCativo()

	intervalo := 20 * time.Second
	if v := os.Getenv("INTERVALO_SEGUNDOS"); v != "" {
		if segundos, err := strconv.Atoi(v); err == nil && segundos > 0 {
			intervalo = time.Duration(segundos) * time.Second
		}
	}
	fmt.Printf("Monitoramento contínuo a cada %s\n", intervalo)
	iniciarMonitoramentoContinuo(rede, intervalo)
	iniciarVerificacaoUPnP()
	iniciarEscutaMDNS(rede.Interface)
	iniciarSondagemSSDP()
	iniciarVerificacaoWifi()

	http.HandleFunc("/", handler(rede))
	http.HandleFunc("/atualizar", atualizarHandler(rede))
	http.HandleFunc("/historico", historicoHandler)
	http.HandleFunc("/mapa", mapaHandler(rede))
	http.HandleFunc("/isolar", isolarHandler(rede))
	http.HandleFunc("/reconectar", reconectarHandler(rede))
	http.HandleFunc("/confiavel", confiavelHandler(rede))

	porta := "8090"
	if v := os.Getenv("PORTA"); v != "" {
		if _, err := strconv.Atoi(v); err == nil {
			porta = v
		}
	}
	fmt.Printf("Dashboard rodando em http://localhost:%s\n", porta)
	http.ListenAndServe(":"+porta, nil)
}
