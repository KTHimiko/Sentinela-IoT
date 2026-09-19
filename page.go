package main

import (
	"fmt"
	"html"
	"strings"
	"time"
)

// ---------- the dashboard page ----------

// riskSlug maps the risk key to something usable as a CSS identifier:
// "médio" carries an accent, and a custom property named --risk-médio is
// asking for trouble across browsers.
var riskSlug = map[string]string{"baixo": "baixo", "médio": "medio", "alto": "alto"}

// pageStyle holds the design tokens and the layout. Colours are declared
// once as custom properties and referenced by role everywhere else,
// including inside the SVG map, so the light/dark pair swaps in one place.
//
// The risk colours are a status scale, not a categorical one: they mean
// good / warning / critical, and they are always shipped next to a text
// label, never as colour alone. Both sets were checked for colour-vision
// deficiency separation — the light set reaches ΔE 8.1 between the two
// closest (green and mustard) and the dark set 11.3, against a target of
// 8. The dark set is stepped for the dark surface rather than being the
// light set reused, which would drop the red below 3:1 contrast.
const pageStyle = `
:root {
  color-scheme: light;
  --page:#f9f9f7; --surface:#fcfcfb; --surface-2:#f2f1ed;
  --ink-1:#0b0b0b; --ink-2:#52514e; --ink-3:#898781;
  --grid:#e1e0d9; --border:rgba(11,11,11,.10);
  --accent:#4a3aa7; --router:#2a78d6;
  --risk-baixo:#2e7d32; --risk-medio:#b8860b; --risk-alto:#b3261e;
  --quarantine-bg:rgba(179,38,30,.06);
  --wash:rgba(11,11,11,.04);
  /* ink for text sitting on a solid accent/status fill */
  --on-solid:#ffffff;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --page:#0d0d0d; --surface:#1a1a19; --surface-2:#222221;
    --ink-1:#ffffff; --ink-2:#c3c2b7; --ink-3:#898781;
    --grid:#2c2c2a; --border:rgba(255,255,255,.10);
    --accent:#9085e9; --router:#3987e5;
    --risk-baixo:#0ca30c; --risk-medio:#fab219; --risk-alto:#e66767;
    --quarantine-bg:rgba(230,103,103,.12);
    --wash:rgba(255,255,255,.05);
    /* the dark steps are light fills, so their label has to go dark:
       white on #e66767 lands near 2.6:1 and is unreadable */
    --on-solid:#14140f;
  }
}

* { box-sizing:border-box; }
body {
  font-family:system-ui,-apple-system,"Segoe UI",sans-serif;
  background:var(--page); color:var(--ink-1);
  margin:0; padding:1.5rem 1rem 3rem; font-size:15px; line-height:1.5;
}
.wrap { max-width:1180px; margin:0 auto; }

header { display:flex; justify-content:space-between; align-items:flex-start; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }
h1 { font-size:1.35rem; margin:0 0 .25rem; letter-spacing:-.01em; }
.sub { color:var(--ink-2); font-size:.85rem; margin:0; }
h2 { font-size:.95rem; margin:0 0 .75rem; letter-spacing:-.01em; }

.btn {
  display:inline-block; padding:.45rem .9rem; border-radius:7px; font-size:.85rem;
  text-decoration:none; border:1px solid var(--border); background:var(--surface);
  color:var(--ink-1); cursor:pointer; font-family:inherit;
}
.btn:hover { background:var(--wash); }
.btn-primary { background:var(--accent); border-color:transparent; color:var(--on-solid); }
.btn-primary:hover { opacity:.9; background:var(--accent); }
.btn-danger { background:var(--risk-alto); border-color:transparent; color:var(--on-solid); }
.btn-ok { background:var(--risk-baixo); border-color:transparent; color:var(--on-solid); }

/* summary tiles — the counts are the headline, and they double as the filter */
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:.6rem; margin-bottom:1.25rem; }
.tile {
  background:var(--surface); border:1px solid var(--border); border-radius:10px;
  padding:.75rem .9rem; text-align:left; cursor:pointer; font-family:inherit;
  display:flex; flex-direction:column; gap:.1rem; border-left:3px solid var(--grid);
}
.tile:hover { background:var(--wash); }
.tile[aria-pressed="true"] { outline:2px solid var(--accent); outline-offset:-2px; }
.tile .v { font-size:1.6rem; font-weight:600; line-height:1.1; }
.tile .l { font-size:.75rem; color:var(--ink-2); }
.tile.alto { border-left-color:var(--risk-alto); }
.tile.medio { border-left-color:var(--risk-medio); }
.tile.baixo { border-left-color:var(--risk-baixo); }
.tile.iso { border-left-color:var(--accent); }

.card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:1rem 1.1rem; margin-bottom:1rem; }
.panels { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:.75rem; margin-bottom:1rem; }
.panel { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:.8rem .95rem; font-size:.85rem; }
.panel h3 { font-size:.8rem; margin:0 0 .4rem; color:var(--ink-2); font-weight:600; }
.panel ul { margin:.35rem 0 0; padding-left:1.1rem; color:var(--ink-2); }
.panel li { margin-bottom:.2rem; }
.panel.ok { border-left:3px solid var(--risk-baixo); }
.panel.warn { border-left:3px solid var(--risk-alto); }

.legend { display:flex; gap:1rem; flex-wrap:wrap; font-size:.78rem; color:var(--ink-2); margin-bottom:.6rem; }
.legend span { display:inline-flex; align-items:center; gap:.35rem; }
.dot { width:9px; height:9px; border-radius:50%; display:inline-block; }

/* device cards */
.dev { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:.85rem 1rem; margin-bottom:.6rem; border-left:3px solid var(--grid); }
.dev.alto { border-left-color:var(--risk-alto); }
.dev.medio { border-left-color:var(--risk-medio); }
.dev.baixo { border-left-color:var(--risk-baixo); }
.dev-top { display:flex; align-items:baseline; gap:.5rem; flex-wrap:wrap; }
.dev-ip { font-weight:600; font-size:.95rem; }
.dev-risk { font-size:.75rem; color:var(--ink-2); }
.meta { font-size:.8rem; color:var(--ink-2); margin-top:.15rem; }
.mac { font-size:.75rem; color:var(--ink-3); font-variant-numeric:tabular-nums; }
.badge-agent { font-size:.7rem; background:var(--accent); color:var(--on-solid); padding:.05rem .45rem; border-radius:9px; }
.ports { margin:.5rem 0 0; padding-left:1.1rem; font-size:.8rem; color:var(--ink-2); }
.ports li { margin-bottom:.15rem; }
.note { font-size:.82rem; padding:.55rem .7rem; border-radius:7px; margin-top:.55rem; background:var(--surface-2); color:var(--ink-2); }
.note.bad { background:var(--quarantine-bg); color:var(--ink-1); }
.actions { display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; margin-top:.6rem; }
select { padding:.4rem; border-radius:7px; border:1px solid var(--border); background:var(--surface); color:var(--ink-1); font-size:.82rem; font-family:inherit; }
form { display:contents; }

/* filtering by risk, driven by the tiles */
body[data-filtro="alto"] .dev:not(.alto),
body[data-filtro="medio"] .dev:not(.medio),
body[data-filtro="baixo"] .dev:not(.baixo),
body[data-filtro="iso"] .dev:not(.isolado) { display:none; }

table { width:100%; border-collapse:collapse; font-size:.85rem; }
th, td { text-align:left; padding:.5rem .7rem; border-bottom:1px solid var(--grid); }
th { color:var(--ink-2); font-weight:600; font-size:.78rem; }
td:first-child { color:var(--ink-3); white-space:nowrap; font-variant-numeric:tabular-nums; }
`

// tile renders one summary figure. It is a button because the tiles are
// also the risk filter for the list below — a filter row would repeat
// information the tiles already carry.
func tile(class, filter, value, label string) string {
	return fmt.Sprintf(
		`<button class="tile %s" data-filtro="%s" aria-pressed="false"><span class="v">%s</span><span class="l">%s</span></button>`,
		class, filter, value, label)
}

func summaryTiles(results []deviceResult) string {
	var alto, medio, baixo, isolated int
	for _, r := range results {
		switch r.Risk {
		case "alto":
			alto++
		case "médio":
			medio++
		default:
			baixo++
		}
		if r.Isolated {
			isolated++
		}
	}
	var b strings.Builder
	b.WriteString(`<section class="tiles">`)
	b.WriteString(tile("", "", fmt.Sprint(len(results)), "dispositivos"))
	b.WriteString(tile("alto", "alto", fmt.Sprint(alto), "risco alto"))
	b.WriteString(tile("medio", "medio", fmt.Sprint(medio), "risco médio"))
	b.WriteString(tile("baixo", "baixo", fmt.Sprint(baixo), "baixo risco"))
	b.WriteString(tile("iso", "iso", fmt.Sprint(isolated), "isolados"))
	b.WriteString(`</section>`)
	return b.String()
}

func deviceCard(r deviceResult) string {
	slug := riskSlug[r.Risk]
	classes := "dev " + slug
	if r.Isolated {
		classes += " isolado"
	}

	agent := ""
	if r.Agent != "" {
		agent = fmt.Sprintf(`<span class="badge-agent">agente %s</span>`, html.EscapeString(r.Agent))
	}

	name := ""
	if r.Hostname != "" {
		name = fmt.Sprintf(`<span class="dev-risk">%s</span>`, html.EscapeString(r.Hostname))
	}

	var meta []string
	if r.ProbableType != "" {
		meta = append(meta, r.ProbableType)
	}
	if r.ProbableOS != "" {
		meta = append(meta, r.ProbableOS)
	}
	if r.Vendor != "" && r.Vendor != "Desconhecido" {
		meta = append(meta, r.Vendor)
	}
	metaLine := `<div class="meta"><i>Tipo não identificado</i></div>`
	if len(meta) > 0 {
		metaLine = fmt.Sprintf(`<div class="meta">%s</div>`, strings.Join(meta, " · "))
	}

	mac := r.MAC
	if mac == "" {
		mac = "MAC desconhecido"
	}

	ports := `<div class="meta">Nenhuma porta de risco aberta.</div>`
	if len(r.Ports) > 0 {
		ports = `<ul class="ports"><li>` + strings.Join(r.Ports, "</li><li>") + `</li></ul>`
	}

	// notice explains the situation; controls are the buttons. They are
	// built apart so every button ends up in a single row, instead of one
	// row per concern.
	var notice, controls string
	switch {
	case r.Isolated:
		state := "✅ bloqueio IPv4 confirmado ativo agora"
		class := "note"
		if !r.IPv4BlockActive {
			state = "🚨 a regra de bloqueio IPv4 sumiu do iptables — o dispositivo pode ter voltado à rede"
			class = "note bad"
		}
		v6 := "IPv6 confirmado"
		if !r.IPv6BlockActive {
			v6 = "IPv6 sem regra ativa"
		}
		notice = fmt.Sprintf(
			`<div class="%s">🔒 Isolado por ARP spoofing e firewall. <b>%d</b> pacote(s) bloqueado(s) até agora · %s · %s</div>`,
			class, r.BlockedPackets, state, v6)
		controls = fmt.Sprintf(
			`<form method="POST" action="/reconectar"><input type="hidden" name="ip" value="%s"><button class="btn btn-ok" type="submit">Reconectar</button></form>`, r.IP)
	case r.OutsideSubnet:
		notice = `<div class="note">🌐 Está em outra sub-rede e sem agente. Dá pra ver que existe e quais portas expõe, mas não dá pra identificar o fabricante nem isolar — ARP não atravessa roteador. Conter este dispositivo exigiria um agente dentro da sub-rede dele.</div>`
	case r.MAC == "":
		notice = `<div class="note">⚠️ MAC ainda não resolvido — atualize a varredura pra poder isolar.</div>`
	default:
		controls = fmt.Sprintf(`
			<form method="POST" action="/isolar">
				<input type="hidden" name="ip" value="%s">
				<select name="duracao">
					<option value="60" selected>por 1 hora</option>
					<option value="360">por 6 horas</option>
					<option value="1440">por 24 horas</option>
					<option value="0">sem prazo</option>
				</select>
				<button class="btn btn-danger" type="submit">Isolar</button>
			</form>`, r.IP)
	}

	if r.MAC != "" {
		if r.Trusted {
			controls += fmt.Sprintf(`<form method="POST" action="/confiavel"><input type="hidden" name="ip" value="%s"><input type="hidden" name="confiavel" value="0"><button class="btn" type="submit">Remover confiança</button></form><span class="meta">✅ confiável — mudanças de risco não geram alerta</span>`, r.IP)
		} else {
			controls += fmt.Sprintf(`<form method="POST" action="/confiavel"><input type="hidden" name="ip" value="%s"><input type="hidden" name="confiavel" value="1"><button class="btn" type="submit">Marcar como confiável</button></form>`, r.IP)
		}
	}
	if controls != "" {
		controls = `<div class="actions">` + controls + `</div>`
	}

	return fmt.Sprintf(`
	<div class="%s">
		<div class="dev-top">
			<span class="dot" style="background:var(--risk-%s)"></span>
			<span class="dev-ip">%s</span>%s%s
			<span class="mac">%s</span>
			<span class="dev-risk">%s</span>
		</div>
		%s
		%s
		%s
		%s
	</div>`, classes, slug, r.IP, name, agent, mac, riskLabel[r.Risk], metaLine, ports, notice, controls)
}

func mapLegend() string {
	item := func(colour, label string) string {
		return fmt.Sprintf(`<span><i class="dot" style="background:%s"></i>%s</span>`, colour, label)
	}
	return `<div class="legend">` +
		item("var(--risk-baixo)", "baixo risco") +
		item("var(--risk-medio)", "risco médio") +
		item("var(--risk-alto)", "risco alto") +
		item("var(--router)", "roteador") +
		item("var(--accent)", "Sentinela") +
		`</div>`
}

func pageHTML(network *networkInfo, results []deviceResult, lastUpdate time.Time) string {
	var cards strings.Builder
	for _, r := range results {
		cards.WriteString(deviceCard(r))
	}

	panels := metricsBlockHTML() + agentsBlockHTML() + wifiBlockHTML() + upnpBlockHTML()

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinela IoT</title>
<style>%s</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>🛡️ Sentinela IoT</h1>
      <p class="sub">%s · interface %s · gateway %s · última varredura %s</p>
    </div>
    <div class="actions">
      <a class="btn btn-primary" href="/atualizar">Nova varredura</a>
      <a class="btn" href="/historico">Histórico</a>
    </div>
  </header>

  %s

  <section class="panels">%s</section>

  <section class="card">
    <h2>Mapa da rede</h2>
    %s
    <div id="mapaSVG">%s</div>
  </section>

  <section>
    <h2>Dispositivos</h2>
    %s
  </section>
</div>
<script>
  // the tiles double as the risk filter; clicking the active one clears it
  document.querySelectorAll('.tile').forEach(function (t) {
    t.addEventListener('click', function () {
      var wanted = t.dataset.filtro;
      var current = document.body.dataset.filtro || '';
      var next = (wanted && wanted !== current) ? wanted : '';
      document.body.dataset.filtro = next;
      document.querySelectorAll('.tile').forEach(function (o) {
        o.setAttribute('aria-pressed', String(o.dataset.filtro === next && next !== ''));
      });
    });
  });
  setInterval(function () {
    fetch('/mapa').then(function (r) { return r.text(); }).then(function (svg) {
      document.getElementById('mapaSVG').innerHTML = svg;
    });
  }, 8000);
</script>
</body>
</html>`,
		pageStyle,
		html.EscapeString(network.IPNet.String()), html.EscapeString(network.Interface),
		html.EscapeString(network.Gateway.String()), formatWhen(lastUpdate),
		summaryTiles(results), panels, mapLegend(),
		networkMapSVG(network, results), cards.String())
}

// historyHTML lists the recorded events, newest first — the written proof
// of what happened on the network over time.
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
		rows.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%s %s</td></tr>`,
			html.EscapeString(e.When.Format("02/01 15:04:05")),
			html.EscapeString(label),
			html.EscapeString(e.IP),
			html.EscapeString(e.Detail)))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinela IoT — Histórico</title>
<style>%s</style>
</head>
<body>
<div class="wrap">
  <header>
    <div><h1>🕒 Histórico de eventos</h1><p class="sub">Do mais recente para o mais antigo.</p></div>
    <a class="btn" href="/">Voltar ao painel</a>
  </header>
  <div class="card">
    <table>
      <tr><th>Quando</th><th>Evento</th><th>Dispositivo e detalhe</th></tr>
      %s
    </table>
  </div>
</div>
</body>
</html>`, pageStyle, rows.String())
}
