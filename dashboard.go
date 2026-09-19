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
	IPv4BlockActive     bool  // true only if the iptables DROP rule really exists right now
	IPv6BlockActive     bool  // same for ip6tables (extra defence beyond the forged RA)
	Trusted             bool  // set by hand — suppresses risk-change alerts
	BlockedPackets      int64 // the real iptables counter, not the ARP packets we sent
	ProbableOS          string
	OutsideSubnet       bool // came from a REDES_EXTRAS range: visible, but not containable
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

// ---------- web dashboard ----------

func pageHTML(network *networkInfo, results []deviceResult, lastUpdate time.Time) string {
	var cards strings.Builder
	for _, r := range results {
		color := riskColor[r.Risk]

		var action string
		if r.Isolated {
			confirmation := fmt.Sprintf(`<div class="confirmado">🚫 %d pacote(s) bloqueado(s) pelo firewall até agora (contador real do iptables).</div>`, r.BlockedPackets)
			if r.IPv4BlockActive {
				confirmation += `<div class="confirmado">✅ Bloqueio IPv4 confirmado ativo agora (checado no iptables, não só lembrado da memória).</div>`
			} else {
				confirmation += `<div class="alertaBloqueio">🚨 A regra de bloqueio IPv4 NÃO está mais no iptables! O dispositivo pode ter voltado a ter acesso à rede.</div>`
			}
			if r.IPv6BlockActive {
				confirmation += `<div class="confirmado">✅ Bloqueio IPv6 (por MAC) confirmado ativo.</div>`
			} else {
				confirmation += `<div class="alertaBloqueio">🚨 A regra de bloqueio IPv6 NÃO está mais no ip6tables.</div>`
			}
			action = fmt.Sprintf(`
			<div class="isolado">🔒 <b>Isolado via ARP spoofing + bloqueio no firewall (IPv4 e IPv6).</b> %d pacotes ARP forjados enviados até agora.</div>
			%s
			<form method="POST" action="/reconectar"><input type="hidden" name="ip" value="%s"><button class="btn btn-reconectar" type="submit">🔓 Reconectar à rede</button></form>`,
				r.SentPackets, confirmation, r.IP)
		} else if r.OutsideSubnet {
			action = `<div class="erro">🌐 <b>Está em outra sub-rede.</b> Dá pra ver que existe e quais portas expõe, mas não dá pra descobrir o fabricante nem isolar: o ARP, que é o que sustenta as duas coisas, não atravessa roteador. Só um equipamento dentro daquela sub-rede conseguiria conter este dispositivo.</div>`
		} else if r.MAC == "" {
			action = `<div class="erro">⚠️ MAC não resolvido ainda — atualize a página pra tentar isolar.</div>`
		} else {
			action = fmt.Sprintf(`
			<form method="POST" action="/isolar" class="formIsolar">
				<input type="hidden" name="ip" value="%s">
				<select name="duracao" class="seletorDuracao">
					<option value="60" selected>por 1 hora</option>
					<option value="360">por 6 horas</option>
					<option value="1440">por 24 horas</option>
					<option value="0">sem prazo (até eu reconectar)</option>
				</select>
				<button class="btn btn-isolar" type="submit">🔒 Isolar este dispositivo</button>
			</form>`, r.IP)
		}

		ports := "<i>Nenhuma porta de risco encontrada.</i>"
		if len(r.Ports) > 0 {
			ports = "<ul><li>" + strings.Join(r.Ports, "</li><li>") + "</li></ul>"
		}

		mac := r.MAC
		if mac == "" {
			mac = "desconhecido"
		}

		var identification string
		if r.ProbableType != "" || r.Hostname != "" || r.ProbableOS != "" || (r.Vendor != "" && r.Vendor != "Desconhecido") {
			var parts []string
			if r.ProbableType != "" {
				parts = append(parts, fmt.Sprintf("<b>%s</b>", r.ProbableType))
			}
			if r.ProbableOS != "" {
				parts = append(parts, r.ProbableOS)
			}
			if r.Hostname != "" {
				parts = append(parts, fmt.Sprintf("nome na rede: %s", html.EscapeString(r.Hostname)))
			}
			if r.Vendor != "" && r.Vendor != "Desconhecido" {
				parts = append(parts, fmt.Sprintf("fabricante: %s", r.Vendor))
			}
			identification = fmt.Sprintf(`<div class="identificacao">%s</div>`, strings.Join(parts, " · "))
		} else {
			identification = `<div class="identificacao"><i>Tipo de dispositivo não identificado (MAC de fabricante desconhecido, sem hostname anunciado).</i></div>`
		}

		var trust string
		if r.MAC != "" {
			if r.Trusted {
				trust = fmt.Sprintf(`
				<div class="confiavel">✅ Marcado como confiável — mudanças de risco não vão mais gerar alerta no histórico.</div>
				<form method="POST" action="/confiavel"><input type="hidden" name="ip" value="%s"><input type="hidden" name="confiavel" value="0"><button class="btn" style="background:#616161" type="submit">Remover da lista de confiança</button></form>`, r.IP)
			} else {
				trust = fmt.Sprintf(`<form method="POST" action="/confiavel"><input type="hidden" name="ip" value="%s"><input type="hidden" name="confiavel" value="1"><button class="btn" style="background:#00695c" type="submit">✅ Marcar como confiável</button></form>`, r.IP)
			}
		}

		cards.WriteString(fmt.Sprintf(`
		<div class="card" style="border-left-color:%s">
			<h3>📡 %s <span class="ip">(MAC %s)</span></h3>
			<div class="badge" style="background:%s">%s</div>
			%s
			%s
			%s
			%s
		</div>`, color, r.IP, mac, color, riskLabel[r.Risk], identification, ports, action, trust))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>Sentinela IoT</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f4f5f7; margin:0; padding:2rem; color:#1a1a2e; }
  h1 { font-size:1.6rem; }
  .subtitulo { color:#555; margin-bottom:2rem; }
  .card { background:white; border-left:6px solid #ccc; border-radius:8px; padding:1rem 1.2rem; margin-bottom:1rem; box-shadow:0 1px 4px rgba(0,0,0,0.08); }
  .card h3 { margin:0 0 0.5rem 0; }
  .ip { color:#888; font-weight:normal; font-size:0.85rem; }
  .badge { display:inline-block; color:white; padding:0.15rem 0.6rem; border-radius:12px; font-size:0.8rem; margin-bottom:0.6rem; }
  .identificacao { font-size:0.85rem; color:#333; margin-bottom:0.4rem; }
  .isolado { background:#fdf1f0; border:1px solid #f0c4c0; padding:0.6rem; border-radius:6px; margin-top:0.5rem; font-size:0.9rem; }
  .confirmado { color:#2e7d32; font-size:0.85rem; margin-top:0.4rem; }
  .alertaBloqueio { background:#fff3cd; border:1px solid #e0b400; color:#7a5c00; padding:0.5rem; border-radius:6px; font-size:0.85rem; margin-top:0.4rem; }
  .erro { background:#fff3cd; padding:0.6rem; border-radius:6px; margin-top:0.5rem; font-size:0.9rem; }
  .confiavel { color:#00695c; font-size:0.85rem; margin-top:0.4rem; }
  .painelUPnP { border-radius:8px; padding:0.9rem 1.1rem; margin-bottom:1.5rem; font-size:0.9rem; }
  .painelUPnP.ok { background:#e8f5e9; color:#2e7d32; }
  .painelUPnP.neutro { background:#eceff1; color:#455a64; }
  .painelUPnP.alerta { background:#fdecea; color:#7a0c00; border:1px solid #f0c4c0; }
  .painelUPnP ul { margin-top:0.5rem; }
  .mapaContainer { background:white; border-radius:8px; padding:1rem 1.2rem; margin-bottom:1.5rem; box-shadow:0 1px 4px rgba(0,0,0,0.08); }
  .mapaContainer h2 { margin:0 0 0.6rem 0; font-size:1.1rem; }
  a.btn, .btn { display:inline-block; margin-top:0.8rem; color:white; padding:0.5rem 1rem; border-radius:6px; text-decoration:none; border:none; font-size:0.9rem; cursor:pointer; }
  .btn-isolar { background:#b3261e; }
  .formIsolar { display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap; }
  .seletorDuracao { padding:0.4rem; border-radius:6px; border:1px solid #ccc; font-size:0.85rem; }
  .btn-reconectar { background:#2e7d32; }
  .topo { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; }
  ul { margin:0.3rem 0 0 1.2rem; font-size:0.9rem; color:#444; }
</style>
</head>
<body>
  <div class="topo">
    <div>
      <h1>🛡️ Sentinela IoT — Painel de Segurança</h1>
      <p class="subtitulo">Rede detectada: <b>%s</b> (interface %s, gateway %s) — %d dispositivo(s) encontrado(s). Monitoramento contínuo em segundo plano — última varredura: %s.</p>
    </div>
    <div>
      <a class="btn" style="background:#283593" href="/atualizar">🔄 Forçar nova varredura</a>
      <a class="btn" style="background:#455a64" href="/historico">🕒 Histórico</a>
    </div>
  </div>
  <div class="mapaContainer">
    <h2>🗺️ Mapa da rede (ao vivo)</h2>
    <div id="mapaSVG">%s</div>
  </div>
  %s
  %s
  %s
  <script>
    setInterval(function () {
      fetch('/mapa').then(function (resp) { return resp.text(); }).then(function (svg) {
        document.getElementById('mapaSVG').innerHTML = svg;
      });
    }, 4000);
  </script>
</body>
</html>`, network.IPNet.String(), network.Interface, network.Gateway.String(), len(results), formatWhen(lastUpdate), networkMapSVG(network, results), wifiBlockHTML(), upnpBlockHTML(), cards.String())
}

// upnpBlockHTML shows whether the router is exposing any port to the
// internet through UPnP — the most common risk at home, and the most
// invisible one to a non-technical user, since it happens without ever
// passing through the dashboard.
func upnpBlockHTML() string {
	mappings, errMsg, lastCheck := readUPnPCache()

	if lastCheck.IsZero() {
		return `<div class="painelUPnP neutro">🌐 Checagem de exposição UPnP ainda não rodou (roda a cada 2 minutos em segundo plano).</div>`
	}

	if errMsg != "" {
		return fmt.Sprintf(`<div class="painelUPnP ok">✅ Nenhuma exposição UPnP encontrada — %s. (última checagem: %s)</div>`,
			html.EscapeString(errMsg), formatWhen(lastCheck))
	}

	if len(mappings) == 0 {
		return fmt.Sprintf(`<div class="painelUPnP ok">✅ O roteador fala UPnP, mas não tem nenhuma porta exposta pra internet agora. (última checagem: %s)</div>`,
			formatWhen(lastCheck))
	}

	var lines strings.Builder
	for _, m := range mappings {
		description := m.Description
		if description == "" {
			description = "sem descrição"
		}
		lines.WriteString(fmt.Sprintf("<li>porta externa <b>%s/%s</b> → %s:%s (%s)</li>",
			html.EscapeString(m.Protocol), html.EscapeString(m.ExternalPort),
			html.EscapeString(m.InternalIP), html.EscapeString(m.InternalPort), html.EscapeString(description)))
	}
	return fmt.Sprintf(`<div class="painelUPnP alerta">🚨 <b>%d porta(s) exposta(s) pra internet via UPnP</b> — qualquer um de fora consegue tentar acessar esses dispositivos. (última checagem: %s)<ul>%s</ul></div>`,
		len(mappings), formatWhen(lastCheck), lines.String())
}

// wifiBlockHTML shows the security of the Wi-Fi network the laptop is
// using — something no device scan can see.
func wifiBlockHTML() string {
	ssid, protocol, risk, reason, lastCheck := readWifiCache()

	if lastCheck.IsZero() {
		return `<div class="painelUPnP neutro">📶 Checagem de segurança do Wi-Fi ainda não rodou (ou a conexão não é Wi-Fi / nmcli indisponível).</div>`
	}

	class := "neutro"
	if risk == "baixo" {
		class = "ok"
	} else if risk == "alto" {
		class = "alerta"
	}
	return fmt.Sprintf(`<div class="painelUPnP %s">📶 Wi-Fi <b>%s</b> (%s) — %s (última checagem: %s)</div>`,
		class, html.EscapeString(ssid), html.EscapeString(protocol), html.EscapeString(reason), formatWhen(lastCheck))
}

// formatWhen returns "há Xs"/"há Xmin" instead of a raw timestamp, which
// a non-technical user can read at a glance in the dashboard.
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

// historyHTML lists the recorded events, newest first — the written proof
// of what happened on the network over time (devices that appeared or
// vanished, risks that changed, isolations and reconnections).
func historyHTML() string {
	historyMu.Lock()
	events := make([]historyEvent, len(historyInMemory))
	copy(events, historyInMemory)
	historyMu.Unlock()

	var rows strings.Builder
	if len(events) == 0 {
		rows.WriteString(`<tr><td colspan="3"><i>Nenhum evento registrado ainda — aguarde a próxima varredura.</i></td></tr>`)
	}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		label := eventLabel[e.Type]
		if label == "" {
			label = e.Type
		}
		rows.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s — %s</td></tr>`,
			html.EscapeString(e.When.Format("02/01 15:04:05")),
			html.EscapeString(label),
			html.EscapeString(e.IP),
			html.EscapeString(e.Detail)))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>Sentinela IoT — Histórico</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f4f5f7; margin:0; padding:2rem; color:#1a1a2e; }
  h1 { font-size:1.6rem; }
  table { width:100%%; border-collapse:collapse; background:white; border-radius:8px; overflow:hidden; box-shadow:0 1px 4px rgba(0,0,0,0.08); }
  th, td { text-align:left; padding:0.6rem 0.9rem; border-bottom:1px solid #eee; font-size:0.9rem; }
  th { background:#283593; color:white; }
  .topo { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; margin-bottom:1.5rem; }
  a.btn { display:inline-block; color:white; background:#283593; padding:0.5rem 1rem; border-radius:6px; text-decoration:none; font-size:0.9rem; }
</style>
</head>
<body>
  <div class="topo">
    <h1>🕒 Histórico de eventos</h1>
    <a class="btn" href="/">⬅ Voltar ao painel</a>
  </div>
  <table>
    <tr><th>Quando</th><th>Evento</th><th>Dispositivo / detalhe</th></tr>
    %s
  </table>
</body>
</html>`, rows.String())
}

func handler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		results, lastUpdate := readCache()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, pageHTML(network, results, lastUpdate))
	}
}

// refreshHandler forces a new scan right away (rather than waiting for the
// next cycle of the continuous monitoring) — useful for whoever clicks
// "force a new scan" and wants to see the result immediately.
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
		results, _ := readCache()
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		fmt.Fprint(w, networkMapSVG(network, results))
	}
}

func isolateHandler(network *networkInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		ipStr := r.FormValue("ip")
		targetIP := net.ParseIP(ipStr).To4()
		if targetIP == nil {
			http.Error(w, "IP inválido", http.StatusBadRequest)
			return
		}
		mac, ok := readARPTable(network.Interface)[ipStr]
		if !ok {
			http.Error(w, "MAC do dispositivo ainda não resolvido, tente escanear de novo", http.StatusConflict)
			return
		}
		// duration chosen by the user in the form, in minutes; 0 (or a
		// missing/invalid value) means "no deadline"
		var duration time.Duration
		if minutes, err := strconv.Atoi(r.FormValue("duracao")); err == nil && minutes > 0 {
			duration = time.Duration(minutes) * time.Minute
		}
		if err := isolateDevice(network, targetIP, mac, duration); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		refreshCache(network)
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
		if err := reconnectDevice(ip, network); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		refreshCache(network)
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
