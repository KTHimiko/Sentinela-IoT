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

// ---------- varredura completa ----------

type resultadoDispositivo struct {
	Nome, IP, MAC, Risco string
	Fabricante           string
	TipoProvavel         string
	Hostname             string
	Portas               []string // texto formatado pra exibir no dashboard
	PortasNumeros        []string // só os números, pra comparar entre varreduras
	Isolado              bool
	PacotesEnviados      int64
	BloqueioV4Ativo      bool  // true só se a regra de DROP no iptables realmente existe agora
	BloqueioV6Ativo      bool  // idem pro ip6tables (defesa extra além do RA falso)
	Confiavel            bool  // marcado manualmente — suprime alertas de mudança de risco
	PacotesBloqueados    int64 // contador real do iptables, não só o de pacotes ARP enviados
	SistemaProvavel      string
	ForaDaSubRede        bool // veio de uma faixa de REDES_EXTRAS: dá pra ver, não dá pra isolar
}

// limiteHosts teto de hosts processados ao mesmo tempo. Cada host abre
// até 17 conexões TCP na varredura de portas, então sem teto uma rede
// com 100 aparelhos tentaria 1700 conexões simultâneas.
const limiteHosts = 24

func escanear(rede *infoRede) []resultadoDispositivo {
	candidatos := hostsParaVarrer(rede)
	hosts, ttls := findActiveHosts(candidatos)
	tabelaARP := lerTabelaARP(rede.Interface)
	verificarSpoofingDoGateway(rede, tabelaARP)
	detectarMACDuplicado(rede, tabelaARP)

	// Alguns dispositivos (Windows, principalmente) bloqueiam ping por
	// padrão no firewall e nunca apareceriam só com findActiveHosts.
	// Mas resolver o IP pra mandar o ping já força o kernel a mandar um
	// ARP request antes — isso quase nunca é bloqueado — então qualquer
	// IP que ficou na tabela ARP também conta como "ativo", mesmo sem
	// ter respondido ao ping.
	vistos := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		vistos[h] = true
	}
	for ip := range tabelaARP {
		if !vistos[ip] && rede.IPNet.Contains(net.ParseIP(ip)) {
			hosts = append(hosts, ip)
			vistos[ip] = true
		}
	}

	// processa cada host em paralelo: port scan (17 portas), reverse DNS
	// (até 300ms) e checagens de iptables pra isolados eram feitas uma
	// de cada vez, então o tempo do ciclo inteiro crescia com o número
	// de dispositivos — numa rede com vários aparelhos, isso empurrava
	// o ciclo de "a cada 20s" pra bem mais que isso. Em paralelo, o
	// tempo do ciclo fica limitado pelo host mais lento, não pela soma.
	var mu sync.Mutex
	var wg sync.WaitGroup
	vagas := make(chan struct{}, limiteHosts)
	var resultados []resultadoDispositivo
	for _, host := range hosts {
		if host == rede.IP.String() {
			continue // não faz sentido escanear/isolar o próprio notebook
		}
		if host == rede.Gateway.String() {
			continue // isolar o roteador derrubaria a internet de toda a rede
		}
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			vagas <- struct{}{}
			defer func() { <-vagas }()

			r := resultadoDispositivo{Nome: host, IP: host}
			r.ForaDaSubRede = !rede.IPNet.Contains(net.ParseIP(host))
			r.SistemaProvavel = classificarSOPorTTL(ttls[host])
			if mac, ok := tabelaARP[host]; ok {
				r.MAC = mac.String()
				r.Fabricante, r.TipoProvavel = identificarPorMAC(r.MAC)
				r.Confiavel = ehConfiavel(r.MAC)
			}
			r.Hostname = resolverHostname(host)
			if tipo := refinarTipoPorHostname(r.Hostname); tipo != "" {
				r.TipoProvavel = tipo
			}
			// mDNS/SSDP são o sinal mais forte (o próprio dispositivo se
			// anunciando), por isso têm prioridade sobre MAC OUI e hostname.
			if tipo := tipoPorMDNS(host); tipo != "" {
				r.TipoProvavel = tipo
			}
			if tipo := tipoPorSSDP(host); tipo != "" {
				r.TipoProvavel = tipo
			}

			piorRisco := ""
			if r.Confiavel {
				// dispositivo já revisado e marcado como confiável — pula
				// a varredura de portas pra não gastar ciclo com ele.
				// Trade-off consciente: se ele for comprometido depois e
				// abrir uma porta nova, isso não vai ser detectado até
				// alguém desmarcar a confiança e escanear de novo.
				r.Portas = append(r.Portas, "Varredura de portas pulada — dispositivo marcado como confiável.")
				piorRisco = "baixo"
			} else {
				portasAtivas := portasAbertas(host)
				for _, p := range portasAtivas {
					r.Portas = append(r.Portas, fmt.Sprintf("%s (%s): %s", p.number, p.service, p.explicacao))
					r.PortasNumeros = append(r.PortasNumeros, p.number)
					if piorRisco == "" || riskLevel[p.risk] > riskLevel[piorRisco] {
						piorRisco = p.risk
					}
				}
				for _, p := range portasAtivas {
					if p.number != "443" {
						continue
					}
					if problema := verificarCertificadoTLS(host); problema != "" {
						r.Portas = append(r.Portas, fmt.Sprintf("443 (HTTPS): %s", problema))
						if riskLevel["médio"] > riskLevel[piorRisco] {
							piorRisco = "médio"
						}
					}
					break
				}
			}
			if piorRisco == "" {
				piorRisco = "baixo"
			}
			r.Risco = piorRisco

			// Últimos recursos de identificação, só quando OUI, hostname,
			// mDNS e SSDP não classificaram o tipo. As portas abertas
			// (sinal funcional) têm prioridade sobre o palpite de MAC
			// aleatório (que só diz que é um dispositivo pessoal com
			// privacidade de MAC ligada, sem dizer qual).
			if r.TipoProvavel == "" {
				if tipo := inferirTipoPorPortas(r.PortasNumeros); tipo != "" {
					r.TipoProvavel = tipo
				} else if macAleatorio(r.MAC) {
					r.TipoProvavel = "📱 Provável celular/notebook (privacidade de MAC ligada)"
				}
			}

			isolamentosMu.Lock()
			estado, isolado := isolamentos[host]
			isolamentosMu.Unlock()
			if isolado {
				r.Isolado = true
				r.PacotesEnviados = atomic.LoadInt64(&estado.pacotes)
				r.BloqueioV4Ativo = bloqueioIPv4Ativo(host)
				r.PacotesBloqueados = pacotesBloqueados(host)
				if estado.mac != nil {
					r.BloqueioV6Ativo = bloqueioIPv6Ativo(estado.mac)
				}
			}

			mu.Lock()
			resultados = append(resultados, r)
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return resultados
}

// ---------- dashboard web ----------

func paginaHTML(rede *infoRede, resultados []resultadoDispositivo, ultimaAtualizacao time.Time) string {
	var cards strings.Builder
	for _, r := range resultados {
		cor := riskColor[r.Risco]

		var acao string
		if r.Isolado {
			confirmacao := fmt.Sprintf(`<div class="confirmado">🚫 %d pacote(s) bloqueado(s) pelo firewall até agora (contador real do iptables).</div>`, r.PacotesBloqueados)
			if r.BloqueioV4Ativo {
				confirmacao += `<div class="confirmado">✅ Bloqueio IPv4 confirmado ativo agora (checado no iptables, não só lembrado da memória).</div>`
			} else {
				confirmacao += `<div class="alertaBloqueio">🚨 A regra de bloqueio IPv4 NÃO está mais no iptables! O dispositivo pode ter voltado a ter acesso à rede.</div>`
			}
			if r.BloqueioV6Ativo {
				confirmacao += `<div class="confirmado">✅ Bloqueio IPv6 (por MAC) confirmado ativo.</div>`
			} else {
				confirmacao += `<div class="alertaBloqueio">🚨 A regra de bloqueio IPv6 NÃO está mais no ip6tables.</div>`
			}
			acao = fmt.Sprintf(`
			<div class="isolado">🔒 <b>Isolado via ARP spoofing + bloqueio no firewall (IPv4 e IPv6).</b> %d pacotes ARP forjados enviados até agora.</div>
			%s
			<form method="POST" action="/reconectar"><input type="hidden" name="ip" value="%s"><button class="btn btn-reconectar" type="submit">🔓 Reconectar à rede</button></form>`,
				r.PacotesEnviados, confirmacao, r.IP)
		} else if r.ForaDaSubRede {
			acao = `<div class="erro">🌐 <b>Está em outra sub-rede.</b> Dá pra ver que existe e quais portas expõe, mas não dá pra descobrir o fabricante nem isolar: o ARP, que é o que sustenta as duas coisas, não atravessa roteador. Só um equipamento dentro daquela sub-rede conseguiria conter este dispositivo.</div>`
		} else if r.MAC == "" {
			acao = `<div class="erro">⚠️ MAC não resolvido ainda — atualize a página pra tentar isolar.</div>`
		} else {
			acao = fmt.Sprintf(`
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

		portas := "<i>Nenhuma porta de risco encontrada.</i>"
		if len(r.Portas) > 0 {
			portas = "<ul><li>" + strings.Join(r.Portas, "</li><li>") + "</li></ul>"
		}

		mac := r.MAC
		if mac == "" {
			mac = "desconhecido"
		}

		var identificacao string
		if r.TipoProvavel != "" || r.Hostname != "" || r.SistemaProvavel != "" || (r.Fabricante != "" && r.Fabricante != "Desconhecido") {
			var partes []string
			if r.TipoProvavel != "" {
				partes = append(partes, fmt.Sprintf("<b>%s</b>", r.TipoProvavel))
			}
			if r.SistemaProvavel != "" {
				partes = append(partes, r.SistemaProvavel)
			}
			if r.Hostname != "" {
				partes = append(partes, fmt.Sprintf("nome na rede: %s", html.EscapeString(r.Hostname)))
			}
			if r.Fabricante != "" && r.Fabricante != "Desconhecido" {
				partes = append(partes, fmt.Sprintf("fabricante: %s", r.Fabricante))
			}
			identificacao = fmt.Sprintf(`<div class="identificacao">%s</div>`, strings.Join(partes, " · "))
		} else {
			identificacao = `<div class="identificacao"><i>Tipo de dispositivo não identificado (MAC de fabricante desconhecido, sem hostname anunciado).</i></div>`
		}

		var confianca string
		if r.MAC != "" {
			if r.Confiavel {
				confianca = fmt.Sprintf(`
				<div class="confiavel">✅ Marcado como confiável — mudanças de risco não vão mais gerar alerta no histórico.</div>
				<form method="POST" action="/confiavel"><input type="hidden" name="ip" value="%s"><input type="hidden" name="confiavel" value="0"><button class="btn" style="background:#616161" type="submit">Remover da lista de confiança</button></form>`, r.IP)
			} else {
				confianca = fmt.Sprintf(`<form method="POST" action="/confiavel"><input type="hidden" name="ip" value="%s"><input type="hidden" name="confiavel" value="1"><button class="btn" style="background:#00695c" type="submit">✅ Marcar como confiável</button></form>`, r.IP)
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
		</div>`, cor, r.IP, mac, cor, riskLabel[r.Risco], identificacao, portas, acao, confianca))
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
</html>`, rede.IPNet.String(), rede.Interface, rede.Gateway.String(), len(resultados), formatarQuando(ultimaAtualizacao), mapaSVG(rede, resultados), blocoWifiHTML(), blocoUPnPHTML(), cards.String())
}

// blocoUPnPHTML mostra se o roteador está expondo alguma porta pra
// internet via UPnP — o risco doméstico mais comum, e o mais invisível
// pra um usuário leigo, já que acontece sem passar pelo dashboard.
func blocoUPnPHTML() string {
	mapeamentos, erro, ultimaChecagem := lerCacheUPnP()

	if ultimaChecagem.IsZero() {
		return `<div class="painelUPnP neutro">🌐 Checagem de exposição UPnP ainda não rodou (roda a cada 2 minutos em segundo plano).</div>`
	}

	if erro != "" {
		return fmt.Sprintf(`<div class="painelUPnP ok">✅ Nenhuma exposição UPnP encontrada — %s. (última checagem: %s)</div>`,
			html.EscapeString(erro), formatarQuando(ultimaChecagem))
	}

	if len(mapeamentos) == 0 {
		return fmt.Sprintf(`<div class="painelUPnP ok">✅ O roteador fala UPnP, mas não tem nenhuma porta exposta pra internet agora. (última checagem: %s)</div>`,
			formatarQuando(ultimaChecagem))
	}

	var linhas strings.Builder
	for _, m := range mapeamentos {
		descricao := m.Descricao
		if descricao == "" {
			descricao = "sem descrição"
		}
		linhas.WriteString(fmt.Sprintf("<li>porta externa <b>%s/%s</b> → %s:%s (%s)</li>",
			html.EscapeString(m.Protocolo), html.EscapeString(m.PortaExterna),
			html.EscapeString(m.IPInterno), html.EscapeString(m.PortaInterna), html.EscapeString(descricao)))
	}
	return fmt.Sprintf(`<div class="painelUPnP alerta">🚨 <b>%d porta(s) exposta(s) pra internet via UPnP</b> — qualquer um de fora consegue tentar acessar esses dispositivos. (última checagem: %s)<ul>%s</ul></div>`,
		len(mapeamentos), formatarQuando(ultimaChecagem), linhas.String())
}

// blocoWifiHTML mostra a segurança da própria rede Wi-Fi que o
// notebook está usando — algo que nenhuma varredura de dispositivo
// consegue enxergar.
func blocoWifiHTML() string {
	ssid, protocolo, risco, motivo, ultimaChecagem := lerCacheWifi()

	if ultimaChecagem.IsZero() {
		return `<div class="painelUPnP neutro">📶 Checagem de segurança do Wi-Fi ainda não rodou (ou a conexão não é Wi-Fi / nmcli indisponível).</div>`
	}

	classe := "neutro"
	if risco == "baixo" {
		classe = "ok"
	} else if risco == "alto" {
		classe = "alerta"
	}
	return fmt.Sprintf(`<div class="painelUPnP %s">📶 Wi-Fi <b>%s</b> (%s) — %s (última checagem: %s)</div>`,
		classe, html.EscapeString(ssid), html.EscapeString(protocolo), html.EscapeString(motivo), formatarQuando(ultimaChecagem))
}

// formatarQuando devolve "há Xs"/"há Xmin" em vez de um timestamp cru,
// mais fácil de ler rápido pro usuário leigo no dashboard.
func formatarQuando(quando time.Time) string {
	if quando.IsZero() {
		return "ainda não rodou"
	}
	decorrido := time.Since(quando)
	switch {
	case decorrido < time.Minute:
		return fmt.Sprintf("há %ds", int(decorrido.Seconds()))
	default:
		return fmt.Sprintf("há %dmin", int(decorrido.Minutes()))
	}
}

// historicoHTML lista os eventos registrados, do mais recente pro mais
// antigo — é a prova em texto do que aconteceu na rede ao longo do
// tempo (dispositivos que apareceram/sumiram, riscos que mudaram,
// isolamentos e reconexões).
func historicoHTML() string {
	historicoMu.Lock()
	eventos := make([]eventoHistorico, len(historicoMem))
	copy(eventos, historicoMem)
	historicoMu.Unlock()

	var linhas strings.Builder
	if len(eventos) == 0 {
		linhas.WriteString(`<tr><td colspan="3"><i>Nenhum evento registrado ainda — aguarde a próxima varredura.</i></td></tr>`)
	}
	for i := len(eventos) - 1; i >= 0; i-- {
		e := eventos[i]
		rotulo := rotuloEvento[e.Tipo]
		if rotulo == "" {
			rotulo = e.Tipo
		}
		linhas.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s — %s</td></tr>`,
			html.EscapeString(e.Quando.Format("02/01 15:04:05")),
			html.EscapeString(rotulo),
			html.EscapeString(e.IP),
			html.EscapeString(e.Detalhe)))
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
</html>`, linhas.String())
}

func handler(rede *infoRede) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resultados, ultimaAtualizacao := lerCache()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, paginaHTML(rede, resultados, ultimaAtualizacao))
	}
}

// atualizarHandler força uma nova varredura na hora (em vez de esperar
// o próximo ciclo do monitoramento contínuo) — útil pra quem clica em
// "forçar nova varredura" e quer ver o resultado imediatamente.
func atualizarHandler(rede *infoRede) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atualizarCache(rede)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func historicoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, historicoHTML())
}

// mapaHandler devolve só o SVG do mapa, pra ser buscado via JS e
// atualizar o mapa sem recarregar a página inteira.
func mapaHandler(rede *infoRede) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resultados, _ := lerCache()
		w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
		fmt.Fprint(w, mapaSVG(rede, resultados))
	}
}

func isolarHandler(rede *infoRede) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		ipStr := r.FormValue("ip")
		alvoIP := net.ParseIP(ipStr).To4()
		if alvoIP == nil {
			http.Error(w, "IP inválido", http.StatusBadRequest)
			return
		}
		mac, ok := lerTabelaARP(rede.Interface)[ipStr]
		if !ok {
			http.Error(w, "MAC do dispositivo ainda não resolvido, tente escanear de novo", http.StatusConflict)
			return
		}
		// duração escolhida pelo usuário no formulário, em minutos;
		// 0 (ou valor inválido/ausente) significa "sem prazo".
		var duracao time.Duration
		if minutos, err := strconv.Atoi(r.FormValue("duracao")); err == nil && minutos > 0 {
			duracao = time.Duration(minutos) * time.Minute
		}
		if err := isolarDispositivo(rede, alvoIP, mac, duracao); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		atualizarCache(rede)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func reconectarHandler(rede *infoRede) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		ip := r.FormValue("ip")
		if err := reconectarDispositivo(ip, rede); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		atualizarCache(rede)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// confiavelHandler marca ou desmarca um dispositivo como confiável,
// identificado pelo MAC atual daquele IP.
func confiavelHandler(rede *infoRede) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		ip := r.FormValue("ip")
		mac, ok := lerTabelaARP(rede.Interface)[ip]
		if !ok {
			http.Error(w, "MAC não resolvido ainda, tente escanear de novo", http.StatusConflict)
			return
		}
		marcarConfiavel(mac.String(), r.FormValue("confiavel") == "1")
		atualizarCache(rede)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
