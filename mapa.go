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

// Geometria dos nós ao redor do roteador. Eles ficam num arco abaixo
// dele (de 15° a 165°, medidos a partir do eixo x — em coordenadas de
// tela isso cobre do canto inferior-direito ao inferior-esquerdo,
// passando por "reto pra baixo"), distribuídos em anéis concêntricos:
// cada anel recebe só quantos nós cabem no seu arco sem os círculos se
// encostarem, e o excedente vai pro anel seguinte. Com um único anel de
// raio fixo, qualquer rede com mais de uns nove dispositivos virava uma
// mancha de círculos empilhados uns sobre os outros.
const (
	raioBase   = 190.0
	passoAnel  = 100.0
	espacoNo   = 64.0 // diâmetro do círculo (48) + folga pro rótulo não colar no vizinho
	grauInicio = 15.0
	grauFim    = 165.0
)

type posicaoNo struct{ raio, ang float64 }

// posicoesDosNos devolve raio e ângulo de cada um dos n nós, preenchendo
// um anel de cada vez, de dentro pra fora.
func posicoesDosNos(n int) []posicaoNo {
	const abertura = (grauFim - grauInicio) * math.Pi / 180
	pos := make([]posicaoNo, 0, n)
	for anel := 0; len(pos) < n; anel++ {
		raio := raioBase + float64(anel)*passoAnel
		cabem := int(raio*abertura/espacoNo) + 1
		if restam := n - len(pos); restam < cabem {
			cabem = restam // último anel: distribui só o que sobrou
		}
		for i := 0; i < cabem; i++ {
			grau := 90.0
			if cabem > 1 {
				grau = grauInicio + (grauFim-grauInicio)*float64(i)/float64(cabem-1)
			}
			pos = append(pos, posicaoNo{raio, grau * math.Pi / 180})
		}
	}
	return pos
}

// mapaSVG desenha o notebook, o roteador e os dispositivos encontrados
// num mapa visual: dispositivos normais em arco ao redor do roteador,
// dispositivos isolados puxados visualmente pra uma "zona de
// quarentena" separada — sem nenhuma linha ligando ela ao roteador,
// só ao notebook (que é quem intercepta o tráfego via ARP spoofing).
func mapaSVG(rede *infoRede, resultados []resultadoDispositivo) string {
	const gwY = 190
	const nbX, nbY = 90, 60

	var normais, isolados []resultadoDispositivo
	for _, r := range resultados {
		if r.Isolado {
			isolados = append(isolados, r)
		} else {
			normais = append(normais, r)
		}
	}

	// a tela cresce com o anel mais externo, em vez de ter tamanho fixo
	posicoes := posicoesDosNos(len(normais))
	raioMax := raioBase
	if len(posicoes) > 0 {
		raioMax = posicoes[len(posicoes)-1].raio
	}
	largura := int(math.Max(900, 2*(raioMax+90)))
	altura := int(gwY + raioMax + 110)
	gwX := largura / 2

	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" style="width:100%%;height:auto;background:#fafafa;border-radius:8px;font-family:-apple-system,Segoe UI,Arial,sans-serif;">`, largura, altura)

	// notebook (o próprio Sentinela IoT)
	fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9575cd" stroke-width="2"/>`, nbX, nbY, gwX, gwY)
	fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="26" fill="#5e35b1"/><text x="%d" y="%d" text-anchor="middle" font-size="20">🛡️</text><text x="%d" y="%d" text-anchor="middle" font-size="11" fill="#333">Sentinela IoT</text>`,
		nbX, nbY, nbX, nbY+7, nbX, nbY+42)

	// roteador
	fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="30" fill="#1565c0"/><text x="%d" y="%d" text-anchor="middle" font-size="22">📶</text><text x="%d" y="%d" text-anchor="middle" font-size="12" fill="#333">Roteador (%s)</text>`,
		gwX, gwY, gwX, gwY+8, gwX, gwY+50, html.EscapeString(rede.Gateway.String()))

	// dispositivos normais, em anéis ao redor do roteador
	for i, r := range normais {
		p := posicoes[i]
		x := gwX + int(p.raio*math.Cos(p.ang))
		y := gwY + int(p.raio*math.Sin(p.ang))
		cor := riskColor[r.Risco]
		fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#bbb" stroke-width="2"/>`, gwX, gwY, x, y)
		fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="24" fill="%s"/><text x="%d" y="%d" text-anchor="middle" font-size="18">%s</text><text x="%d" y="%d" text-anchor="middle" font-size="10" fill="#333">%s</text>`,
			x, y, cor, x, y+6, iconeDoTipo(r.TipoProvavel), x, y+40, rotuloCurto(r))
	}

	// zona de quarentena — sem ligação com o roteador, só com o
	// notebook, deixando visualmente claro que foi cortado da rede
	// principal
	if len(isolados) > 0 {
		// canto superior direito: o arco dos dispositivos normais ocupa
		// a metade de baixo, então é o único lugar que não colide com
		// ele por mais anéis que existam
		linhas := (len(isolados) + 1) / 2
		qx, qy, qw := largura-250, 20, 220
		qh := 70 + linhas*75
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
