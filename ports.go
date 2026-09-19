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

// ---------- port scanning ----------

func checkPort(host string, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 1*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// openPorts checks every entry of portsToCheck on a host in parallel (one
// goroutine per port) instead of sequentially. With the longer port list,
// checking one at a time could push a single host past 10s — every
// filtered port, the ones that answer nothing at all, burns the full 1s
// timeout — which would delay continuous monitoring badly on a network
// with several devices. The result keeps the order of portsToCheck, not
// the order in which the goroutines happen to finish.
func openPorts(host string) []portInfo {
	isOpen := make(map[string]bool, len(portsToCheck))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range portsToCheck {
		wg.Add(1)
		go func(p portInfo) {
			defer wg.Done()
			if checkPort(host, p.number) {
				mu.Lock()
				isOpen[p.number] = true
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	var open []portInfo
	for _, p := range portsToCheck {
		if isOpen[p.number] {
			open = append(open, p)
		}
	}
	return open
}

// checkTLSCertificate connects to port 443 (only once the scan has found
// it open) and checks whether the certificate the device presents can be
// trusted. An open HTTPS port counts as "low risk" in the dashboard, but a
// self-signed or expired certificate — common on cheap routers and cameras
// — should not be treated as secure just because the port is there.
func checkTLSCertificate(host string) string {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", net.JoinHostPort(host, "443"),
		&tls.Config{InsecureSkipVerify: true}, // we want to inspect the certificate even when it is not trusted
	)
	if err != nil {
		return ""
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	cert := certs[0]
	now := time.Now()

	switch {
	case now.After(cert.NotAfter):
		return fmt.Sprintf("certificado HTTPS EXPIRADO desde %s", cert.NotAfter.Format("02/01/2006"))
	case now.Before(cert.NotBefore):
		return "certificado HTTPS ainda não é válido (data de início no futuro)"
	case cert.Issuer.CommonName == cert.Subject.CommonName:
		return "certificado HTTPS auto-assinado — o navegador vai mostrar aviso de segurança pra quem acessar"
	default:
		return ""
	}
}

// hostIsUp sends the ping and also takes the TTL that comes for free in
// the reply — that is what later estimates the operating system (see
// classifyOSByTTL), with no extra probing.
func hostIsUp(ip string) (up bool, ttl int) {
	output, err := exec.Command("ping", "-c", "2", "-W", "1", ip).Output()
	if err != nil {
		return false, 0
	}
	return true, extractTTL(string(output))
}

// extractTTL looks for "ttl=NNN" in the ping output (the iputils-ping
// format, standard on most Linux distributions).
func extractTTL(output string) int {
	idx := strings.Index(output, "ttl=")
	if idx == -1 {
		return 0
	}
	rest := output[idx+4:]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	value, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return value
}

// classifyOSByTTL uses the observed TTL to estimate the operating system.
// Each OS has a different default initial TTL (Windows 128,
// Linux/Android/macOS 64, some network gear and older Unix 255) and, since
// the device is on the same local network with no routers in between, the
// TTL that reaches us is very close to the original, with few hops to
// discount.
func classifyOSByTTL(ttl int) string {
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

// maxProbes caps how many pings run at once. Every hostIsUp spawns a
// `ping` process, so without a cap a /22 range would fire more than a
// thousand processes at once and the whole scan would stall — already
// tight on a /24 (254 at once), and outright unusable as soon as an extra
// range is added through REDES_EXTRAS.
const maxProbes = 96

func findActiveHosts(candidates []string) ([]string, map[string]int) {
	type result struct {
		ip  string
		ttl int
	}
	found := make(chan result)
	slots := make(chan struct{}, maxProbes)
	var wg sync.WaitGroup
	for _, ip := range candidates {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			if up, ttl := hostIsUp(ip); up {
				found <- result{ip, ttl}
			}
		}(ip)
	}
	go func() { wg.Wait(); close(found) }()

	var hosts []string
	ttls := make(map[string]int)
	for r := range found {
		hosts = append(hosts, r.ip)
		ttls[r.ip] = r.ttl
	}
	return hosts, ttls
}
