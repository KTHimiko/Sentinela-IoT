package main

import (
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------- full scan ----------

type deviceResult struct {
	Name, IP, MAC, Risk string
	Vendor              string
	ProbableType        string
	Hostname            string
	Ports               []string // formatted text for the dashboard
	PortNumbers         []string // just the numbers, to compare between scans
	Isolated            bool
	SentPackets         int64
	IPv4BlockActive     bool   // true only if the iptables DROP rule really exists right now
	IPv6BlockActive     bool   // same for ip6tables (extra defence beyond the forged RA)
	Trusted             bool   // set by hand — suppresses risk-change alerts
	BlockedPackets      int64  // the real iptables counter, not the ARP packets we sent
	ProbableOS          string //
	OutsideSubnet       bool   // came from a REDES_EXTRAS range: visible, but not containable
	Agent               string // which agent reported it; empty means this machine
	AgentURL            string // where to send isolate/reconnect orders for it
}

// allResults merges what this machine scanned with what the agents
// reported. Only the central ever has anything in the second half.
func allResults() ([]deviceResult, time.Time) {
	local, updated := readCache()
	remote, _ := readAgentCache()
	if len(remote) == 0 {
		return local, updated
	}
	merged := make([]deviceResult, 0, len(local)+len(remote))
	merged = append(merged, local...)
	merged = append(merged, remote...)
	return merged, updated
}

// maxHosts caps how many hosts are processed at once. Each host opens up
// to 17 TCP connections during the port scan, so without a cap a network
// with 100 devices would attempt 1700 simultaneous connections.
const maxHosts = 24

func scanNetwork(network *networkInfo) []deviceResult {
	candidates := hostsToScan(network)
	hosts, ttls := findActiveHosts(candidates)
	arpTable := readARPTable(network.Interface)
	checkGatewaySpoofing(network, arpTable)
	detectDuplicateMAC(network, arpTable)

	// Some devices (Windows especially) block ping by default in their
	// local firewall and would never show up through findActiveHosts
	// alone. But resolving the IP to send the ping already forces the
	// kernel to emit an ARP request first — that is almost never blocked
	// — so any IP left in the ARP table also counts as active, even
	// without having answered the ping.
	seen := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		seen[h] = true
	}
	for ip := range arpTable {
		if !seen[ip] && network.IPNet.Contains(net.ParseIP(ip)) {
			hosts = append(hosts, ip)
			seen[ip] = true
		}
	}

	// Process each host in parallel: the port scan (17 ports), the reverse
	// DNS lookup (up to 300ms) and the iptables checks for isolated
	// devices used to run one at a time, so the whole cycle grew with the
	// number of devices — on a network with several of them, that pushed
	// the "every 20s" cycle well past 20s. In parallel the cycle is bound
	// by the slowest host, not by the sum of all of them.
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, maxHosts)
	var results []deviceResult
	for _, host := range hosts {
		if host == network.IP.String() {
			continue // no point scanning or isolating the laptop itself
		}
		if host == network.Gateway.String() {
			continue // isolating the router would take the whole network down
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()

			r := deviceResult{Name: host, IP: host}
			r.OutsideSubnet = !network.IPNet.Contains(net.ParseIP(host))
			r.ProbableOS = classifyOSByTTL(ttls[host])
			if mac, ok := arpTable[host]; ok {
				r.MAC = mac.String()
				r.Vendor, r.ProbableType = lookupByMAC(r.MAC)
				r.Trusted = isTrusted(r.MAC)
			}
			r.Hostname = resolveHostname(host)
			if t := refineTypeByHostname(r.Hostname); t != "" {
				r.ProbableType = t
			}
			// mDNS/SSDP are the strongest signal (the device announcing
			// itself), so they take priority over the MAC OUI and hostname
			if t := typeByMDNS(host); t != "" {
				r.ProbableType = t
			}
			if t := typeBySSDP(host); t != "" {
				r.ProbableType = t
			}

			worstRisk := ""
			if r.Trusted {
				// already reviewed and marked as trusted — skip the port
				// scan so the cycle does not spend time on it. A conscious
				// trade-off: if it gets compromised later and opens a new
				// port, that will not be detected until someone unmarks the
				// trust and scans again.
				r.Ports = append(r.Ports, "Varredura de portas pulada — dispositivo marcado como confiável.")
				worstRisk = "baixo"
			} else {
				activePorts := openPorts(host)
				for _, p := range activePorts {
					r.Ports = append(r.Ports, fmt.Sprintf("%s (%s): %s", p.number, p.service, p.explanation))
					r.PortNumbers = append(r.PortNumbers, p.number)
					if worstRisk == "" || riskLevel[p.risk] > riskLevel[worstRisk] {
						worstRisk = p.risk
					}
				}
				for _, p := range activePorts {
					if p.number != "443" {
						continue
					}
					if problem := checkTLSCertificate(host); problem != "" {
						r.Ports = append(r.Ports, fmt.Sprintf("443 (HTTPS): %s", problem))
						if riskLevel["médio"] > riskLevel[worstRisk] {
							worstRisk = "médio"
						}
					}
					break
				}
			}
			if worstRisk == "" {
				worstRisk = "baixo"
			}
			r.Risk = worstRisk

			// Last-resort identification, only when OUI, hostname, mDNS and
			// SSDP did not classify the type. Open ports (a functional
			// signal) take priority over the randomized-MAC guess, which
			// only says it is a personal device with MAC privacy on,
			// without saying which.
			if r.ProbableType == "" {
				if t := inferTypeByPorts(r.PortNumbers); t != "" {
					r.ProbableType = t
				} else if isRandomizedMAC(r.MAC) {
					r.ProbableType = "📱 Provável celular/notebook (privacidade de MAC ligada)"
				}
			}

			isolationsMu.Lock()
			state, isolated := isolations[host]
			isolationsMu.Unlock()
			if isolated {
				r.Isolated = true
				r.SentPackets = atomic.LoadInt64(&state.packets)
				r.IPv4BlockActive = ipv4BlockActive(host)
				r.BlockedPackets = blockedPackets(host)
				if state.mac != nil {
					r.IPv6BlockActive = ipv6BlockActive(state.mac)
				}
			}

			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return results
}

// ---------- side panels ----------

// panel wraps one status block in the shared card shell.
func panel(class, title, body string) string {
	return fmt.Sprintf(`<div class="panel %s"><h3>%s</h3>%s</div>`, class, title, body)
}

// metricsBlockHTML shows the measured response times. It exists to give
// the evaluation real numbers instead of estimates, and it deliberately
// separates the artefact's own cost from the interval that still depends
// on a person deciding to click.
func metricsBlockHTML() string {
	scan, containment, riskToOrder := metricsSnapshot()
	if scan.Count == 0 && containment.Count == 0 {
		return ""
	}

	line := func(label string, s summary, note string) string {
		if s.Count == 0 {
			return fmt.Sprintf("<li>%s: <i>sem medições ainda</i></li>", label)
		}
		return fmt.Sprintf("<li>%s: <b>%s</b> (mín. %s · máx. %s · %d amostras)%s</li>",
			label, formatDuration(s.Median), formatDuration(s.Min), formatDuration(s.Max), s.Count, note)
	}

	body := "<ul>" +
		line("Varredura completa", scan, "") +
		line("Contenção", containment, " — da ordem até a regra confirmada no firewall") +
		line("Risco detectado até a ordem", riskToOrder, " — <b>inclui a decisão humana</b>, já que isolar parte de um clique") +
		"</ul>"
	return panel("", "⏱️ Tempos de resposta (mediana)", body)
}

// agentsBlockHTML reports the state of the agents this central polls. It
// renders nothing when there are none, so a standalone instance looks
// exactly as it did before.
func agentsBlockHTML() string {
	devices, failures := readAgentCache()
	if len(devices) == 0 && len(failures) == 0 {
		return ""
	}

	byAgent := map[string]int{}
	for _, d := range devices {
		byAgent[d.Agent]++
	}

	var lines strings.Builder
	for name, count := range byAgent {
		lines.WriteString(fmt.Sprintf("<li>✅ <b>%s</b> — %d dispositivo(s)</li>", html.EscapeString(name), count))
	}
	for name, reason := range failures {
		lines.WriteString(fmt.Sprintf("<li>⚠️ <b>%s</b> — sem resposta: %s</li>",
			html.EscapeString(name), html.EscapeString(reason)))
	}

	class := "ok"
	if len(failures) > 0 {
		class = "warn"
	}
	return panel(class, "🛰️ Agentes em outras sub-redes", "<ul>"+lines.String()+"</ul>")
}

// upnpBlockHTML shows whether the router is exposing any port to the
// internet through UPnP — the most common risk at home, and the most
// invisible one, since it happens without ever passing through here.
func upnpBlockHTML() string {
	mappings, errMsg, lastCheck := readUPnPCache()

	if lastCheck.IsZero() {
		return panel("", "🌐 Exposição à internet (UPnP)",
			`<div class="meta">Ainda não verificado — roda a cada 2 minutos em segundo plano.</div>`)
	}
	if errMsg != "" {
		return panel("ok", "🌐 Exposição à internet (UPnP)", fmt.Sprintf(
			`<div class="meta">Nenhuma exposição encontrada — %s.<br>Verificado %s.</div>`,
			html.EscapeString(errMsg), formatWhen(lastCheck)))
	}
	if len(mappings) == 0 {
		return panel("ok", "🌐 Exposição à internet (UPnP)", fmt.Sprintf(
			`<div class="meta">O roteador fala UPnP, mas não há nenhuma porta aberta pra internet agora.<br>Verificado %s.</div>`,
			formatWhen(lastCheck)))
	}

	var lines strings.Builder
	for _, m := range mappings {
		description := m.Description
		if description == "" {
			description = "sem descrição"
		}
		lines.WriteString(fmt.Sprintf("<li><b>%s/%s</b> → %s:%s (%s)</li>",
			html.EscapeString(m.Protocol), html.EscapeString(m.ExternalPort),
			html.EscapeString(m.InternalIP), html.EscapeString(m.InternalPort),
			html.EscapeString(description)))
	}
	return panel("warn", "🌐 Exposição à internet (UPnP)", fmt.Sprintf(
		`<div class="meta"><b>%d porta(s) acessível(is) de fora</b> — verificado %s.</div><ul>%s</ul>`,
		len(mappings), formatWhen(lastCheck), lines.String()))
}

// wifiBlockHTML shows the security of the Wi-Fi network the laptop is
// using — something no device scan can see.
func wifiBlockHTML() string {
	ssid, protocol, risk, reason, lastCheck := readWifiCache()

	if lastCheck.IsZero() {
		return panel("", "📶 Rede Wi-Fi",
			`<div class="meta">Ainda não verificado (ou a conexão é cabeada / nmcli indisponível).</div>`)
	}

	class := ""
	switch risk {
	case "baixo":
		class = "ok"
	case "alto":
		class = "warn"
	}
	return panel(class, "📶 Rede Wi-Fi", fmt.Sprintf(
		`<div class="meta"><b>%s</b> (%s)<br>%s<br>Verificado %s.</div>`,
		html.EscapeString(ssid), html.EscapeString(protocol),
		html.EscapeString(reason), formatWhen(lastCheck)))
}

// formatWhen returns "há Xs"/"há Xmin" instead of a raw timestamp, which
// a non-technical user can read at a glance.
func formatWhen(when time.Time) string {
	if when.IsZero() {
		return "ainda não rodou"
	}
	elapsed := time.Since(when)
	switch {
	case elapsed < time.Minute:
		return fmt.Sprintf("há %ds", int(elapsed.Seconds()))
	default:
		return fmt.Sprintf("há %dmin", int(elapsed.Minutes()))
	}
}

// ---------- handlers ----------

func handler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		results, lastUpdate := allResults()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, pageHTML(network, results, lastUpdate))
	}
}

// refreshHandler forces a new scan right away (rather than waiting for the
// next cycle of the continuous monitoring).
func refreshHandler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refreshCache(network)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func historyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, historyHTML())
}

// mapHandler returns just the map's SVG, to be fetched over JS and refresh
// the map without reloading the whole page.
func mapHandler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		results, _ := allResults()
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		fmt.Fprint(w, networkMapSVG(network, results))
	}
}

// isolateByIP resolves the MAC for an IP on this machine's subnet and
// starts the containment. Shared by the web form and the agent's API, so
// both go through exactly the same checks.
func isolateByIP(network *networkInfo, ip string, duration time.Duration) error {
	targetIP := net.ParseIP(ip).To4()
	if targetIP == nil {
		return fmt.Errorf("IP inválido: %q", ip)
	}
	mac, ok := readARPTable(network.Interface)[ip]
	if !ok {
		return fmt.Errorf("MAC de %s ainda não resolvido, tente escanear de novo", ip)
	}
	return isolateDevice(network, targetIP, mac, duration)
}

func isolateHandler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		ip := r.FormValue("ip")
		// duration chosen by the user in the form, in minutes; 0 (or a
		// missing/invalid value) means "no deadline"
		minutes, _ := strconv.Atoi(r.FormValue("duracao"))
		if minutes < 0 {
			minutes = 0
		}

		var err error
		if agentURL := agentURLFor(ip); agentURL != "" {
			// the device belongs to another subnet's agent: only that
			// agent can reach it with ARP, so the order is forwarded
			err = proxyAction(agentURL, "/api/isolar", map[string]any{"ip": ip, "minutos": minutes})
		} else {
			err = isolateByIP(network, ip, time.Duration(minutes)*time.Minute)
			if err == nil {
				refreshCache(network)
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func reconnectHandler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		ip := r.FormValue("ip")

		var err error
		if agentURL := agentURLFor(ip); agentURL != "" {
			err = proxyAction(agentURL, "/api/reconectar", map[string]any{"ip": ip})
		} else {
			err = reconnectDevice(ip, network)
			if err == nil {
				refreshCache(network)
			}
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// trustHandler marks or unmarks a device as trusted, identified by the MAC
// currently answering for that IP.
func trustHandler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		ip := r.FormValue("ip")
		mac, ok := readARPTable(network.Interface)[ip]
		if !ok {
			http.Error(w, "MAC não resolvido ainda, tente escanear de novo", http.StatusConflict)
			return
		}
		setTrusted(mac.String(), r.FormValue("confiavel") == "1")
		refreshCache(network)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
