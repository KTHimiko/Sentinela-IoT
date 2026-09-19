package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- varredura de portas ----------

func checkPort(host string, port string) bool {
	conexao, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 1*time.Second)
	if err != nil {
		return false
	}
	defer conexao.Close()
	return true
}

// portasAbertas confere todas as portsToCheck de um host em paralelo
// (uma goroutine por porta) em vez de sequencial. Com a lista maior de
// portas, verificar uma de cada vez podia levar a varredura de um host
// a mais de 10s (cada porta filtrada — sem resposta nenhuma — gasta o
// timeout inteiro de 1s), o que atrasaria demais o monitoramento
// contínuo numa rede com vários dispositivos. A ordem do resultado
// segue a ordem de portsToCheck, não a ordem em que as goroutines
// terminam.
func portasAbertas(host string) []portInfo {
	abertaPor := make(map[string]bool, len(portsToCheck))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range portsToCheck {
		wg.Add(1)
		go func(p portInfo) {
			defer wg.Done()
			if checkPort(host, p.number) {
				mu.Lock()
				abertaPor[p.number] = true
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	var abertas []portInfo
	for _, p := range portsToCheck {
		if abertaPor[p.number] {
			abertas = append(abertas, p)
		}
	}
	return abertas
}

// verificarCertificadoTLS conecta na porta 443 (só quando ela já
// apareceu aberta na varredura) e confere se o certificado que o
// dispositivo apresenta é confiável — hoje HTTPS aberto é
// automaticamente "baixo risco" no painel, mas um certificado
// auto-assinado ou vencido (comum em roteador/câmera barata) não devia
// contar como seguro só porque a porta está lá.
func verificarCertificadoTLS(host string) string {
	conexao, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true}, // queremos inspecionar o certificado, mesmo que ele não seja confiável
	)
	if err != nil {
		return ""
	}
	defer conexao.Close()

	certs := conexao.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	cert := certs[0]
	agora := time.Now()

	switch {
	case agora.After(cert.NotAfter):
		return fmt.Sprintf("certificado HTTPS EXPIRADO desde %s", cert.NotAfter.Format("02/01/2006"))
	case agora.Before(cert.NotBefore):
		return "certificado HTTPS ainda não é válido (data de início no futuro)"
	case cert.Issuer.CommonName == cert.Subject.CommonName:
		return "certificado HTTPS auto-assinado — o navegador vai mostrar aviso de segurança pra quem acessar"
	default:
		return ""
	}
}

// hostIsUp manda o ping e também aproveita o TTL que já vem de graça
// na resposta — é o que dá pra usar depois pra estimar o sistema
// operacional (classificarSOPorTTL), sem precisar de nenhuma sondagem
// extra.
func hostIsUp(ip string) (ativo bool, ttl int) {
	saida, err := exec.Command("ping", "-c", "2", "-W", "1", ip).Output()
	if err != nil {
		return false, 0
	}
	return true, extrairTTL(string(saida))
}

// extrairTTL procura "ttl=NNN" na saída do ping (formato do
// iputils-ping, padrão na maioria das distros Linux).
func extrairTTL(saida string) int {
	idx := strings.Index(saida, "ttl=")
	if idx == -1 {
		return 0
	}
	resto := saida[idx+4:]
	fim := 0
	for fim < len(resto) && resto[fim] >= '0' && resto[fim] <= '9' {
		fim++
	}
	valor, err := strconv.Atoi(resto[:fim])
	if err != nil {
		return 0
	}
	return valor
}

// classificarSOPorTTL usa o TTL observado pra estimar o sistema
// operacional — cada SO tem um TTL inicial padrão diferente (Windows
// 128, Linux/Android/macOS 64, alguns equipamentos de rede/Unix mais
// antigos 255) e, como o dispositivo está na mesma rede local (sem
// roteadores no meio), o TTL que chega até nós é bem próximo do valor
// original, sem precisar descontar muitos saltos.
func classificarSOPorTTL(ttl int) string {
	switch {
	case ttl == 0:
		return ""
	case ttl >= 60 && ttl <= 64:
		return fmt.Sprintf("🐧 Linux/Android/macOS ou sistema embarcado (TTL %d)", ttl)
	case ttl >= 120 && ttl <= 128:
		return fmt.Sprintf("🪟 Windows (TTL %d)", ttl)
	case ttl >= 250:
		return fmt.Sprintf("🌐 Equipamento de rede ou Unix mais antigo (TTL %d)", ttl)
	default:
		return fmt.Sprintf("Sistema não identificado pelo TTL (TTL %d)", ttl)
	}
}

// limiteSondagens teto de pings simultâneos. Cada hostIsUp gera um
// processo `ping`, então sem teto uma faixa /22 dispararia mais de 1000
// processos de uma vez e a varredura inteira empacava — o que já era
// apertado numa /24 (254 de uma vez) vira inviável assim que se
// acrescenta uma faixa extra em REDES_EXTRAS.
const limiteSondagens = 96

func findActiveHosts(candidatos []string) ([]string, map[string]int) {
	type resultado struct {
		ip  string
		ttl int
	}
	encontrados := make(chan resultado)
	vagas := make(chan struct{}, limiteSondagens)
	var wg sync.WaitGroup
	for _, ip := range candidatos {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			vagas <- struct{}{}
			defer func() { <-vagas }()
			if ativo, ttl := hostIsUp(ip); ativo {
				encontrados <- resultado{ip, ttl}
			}
		}(ip)
	}
	go func() { wg.Wait(); close(encontrados) }()

	var hosts []string
	ttls := make(map[string]int)
	for r := range encontrados {
		hosts = append(hosts, r.ip)
		ttls[r.ip] = r.ttl
	}
	return hosts, ttls
}
