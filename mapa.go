package main

import (
	"fmt"
	"html"
	"math"
	"strings"
)

// ---------- mapa de rede visual ----------

// iconeDoTipo pega só o emoji na frente de TipoProvavel (ex: "💡
// Dispositivo IoT..." vira "💡"), pra caber dentro do círculo do nó no
// mapa. Sem palpite de tipo, usa um ícone genérico.
func iconeDoTipo(tipo string) string {
	campos := strings.Fields(tipo)
	if len(campos) == 0 {
		return "📡"
	}
	return campos[0]
}

// rotuloCurto escolhe um texto curto pra identificar o nó no mapa sem
// estourar o espaço: hostname truncado se tiver, senão só o último
// número do IP.
func rotuloCurto(r resultadoDispositivo) string {
	if r.Hostname != "" {
		h := r.Hostname
		if len([]rune(h)) > 14 {
			h = string([]rune(h)[:14]) + "…"
		}
		return html.EscapeString(h)
	}
	partes := strings.Split(r.IP, ".")
	if len(partes) == 4 {
		return "." + partes[3]
	}
	return html.EscapeString(r.IP)
}

// anguloArco distribui n nós num arco abaixo do roteador (de 20° a
// 160°, medidos a partir do eixo x — em coordenadas de tela, isso
// cobre do canto inferior-direito ao inferior-esquerdo, passando por
// "reto pra baixo").
func anguloArco(i, n int) float64 {
	if n <= 1 {
		return 90 * math.Pi / 180
	}
	const inicio, fim = 20.0, 160.0
	grau := inicio + (fim-inicio)*float64(i)/float64(n-1)
	return grau * math.Pi / 180
}

// mapaSVG desenha o notebook, o roteador e os dispositivos encontrados
// num mapa visual: dispositivos normais em arco ao redor do roteador,
// dispositivos isolados puxados visualmente pra uma "zona de
// quarentena" separada — sem nenhuma linha ligando ela ao roteador,
// só ao notebook (que é quem intercepta o tráfego via ARP spoofing).
func mapaSVG(rede *infoRede, resultados []resultadoDispositivo) string {
	const largura, altura = 900, 560
	const gwX, gwY = 450, 190
	const nbX, nbY = 90, 60
	const raio = 190

	var normais, isolados []resultadoDispositivo
	for _, r := range resultados {
		if r.Isolado {
			isolados = append(isolados, r)
		} else {
			normais = append(normais, r)
		}
	}

	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" style="width:100%%;height:auto;background:#fafafa;border-radius:8px;font-family:-apple-system,Segoe UI,Arial,sans-serif;">`, largura, altura)

	// notebook (o próprio Sentinela IoT)
	fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9575cd" stroke-width="2"/>`, nbX, nbY, gwX, gwY)
	fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="26" fill="#5e35b1"/><text x="%d" y="%d" text-anchor="middle" font-size="20">🛡️</text><text x="%d" y="%d" text-anchor="middle" font-size="11" fill="#333">Sentinela IoT</text>`,
		nbX, nbY, nbX, nbY+7, nbX, nbY+42)

	// roteador
	fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="30" fill="#1565c0"/><text x="%d" y="%d" text-anchor="middle" font-size="22">📶</text><text x="%d" y="%d" text-anchor="middle" font-size="12" fill="#333">Roteador (%s)</text>`,
		gwX, gwY, gwX, gwY+8, gwX, gwY+50, html.EscapeString(rede.Gateway.String()))

	// dispositivos normais, em arco ao redor do roteador
	n := len(normais)
	for i, r := range normais {
		ang := anguloArco(i, n)
		x := gwX + int(raio*math.Cos(ang))
		y := gwY + int(raio*math.Sin(ang))
		cor := riskColor[r.Risco]
		fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#bbb" stroke-width="2"/>`, gwX, gwY, x, y)
		fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="24" fill="%s"/><text x="%d" y="%d" text-anchor="middle" font-size="18">%s</text><text x="%d" y="%d" text-anchor="middle" font-size="10" fill="#333">%s</text>`,
			x, y, cor, x, y+6, iconeDoTipo(r.TipoProvavel), x, y+40, rotuloCurto(r))
	}

	// zona de quarentena — sem ligação com o roteador, só com o
	// notebook, deixando visualmente claro que foi cortado da rede
	// principal
	if len(isolados) > 0 {
		qx, qy, qw, qh := largura-240, altura-200, 210, 170
		fmt.Fprintf(&svg, `<rect x="%d" y="%d" width="%d" height="%d" rx="12" fill="#fdecea" stroke="#c62828" stroke-width="2" stroke-dasharray="6,4"/>`, qx, qy, qw, qh)
		fmt.Fprintf(&svg, `<text x="%d" y="%d" text-anchor="middle" font-size="13" fill="#c62828" font-weight="bold">🚧 Zona de quarentena</text>`, qx+qw/2, qy+24)

		for i, r := range isolados {
			x := qx + 50 + (i%2)*95
			y := qy + 65 + (i/2)*75
			fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#c62828" stroke-width="2" stroke-dasharray="4,3"/>`, nbX, nbY, x, y)
			fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="22" fill="#b3261e"/><text x="%d" y="%d" text-anchor="middle" font-size="16">🔒</text><text x="%d" y="%d" text-anchor="middle" font-size="9" fill="#333">%s</text><text x="%d" y="%d" text-anchor="middle" font-size="9" fill="#c62828">🚫 %d</text>`,
				x, y, x, y+5, x, y+36, rotuloCurto(r), x, y+48, r.PacotesBloqueados)
		}
	}

	svg.WriteString(`</svg>`)
	return svg.String()
}
