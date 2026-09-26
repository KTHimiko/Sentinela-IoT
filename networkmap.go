package main

import (
	"fmt"
	"html"
	"math"
	"strings"
)

// ---------- visual network map ----------

// typeIcon takes just the emoji in front of ProbableType (e.g. "💡
// Dispositivo IoT..." becomes "💡") so it fits inside the node's circle.
// With no type guess, it falls back to a generic icon.
func typeIcon(deviceType string) string {
	fields := strings.Fields(deviceType)
	if len(fields) == 0 {
		return "📡"
	}
	return fields[0]
}

// shortLabel picks a short text to identify the node without overflowing:
// a truncated hostname when there is one, otherwise the last octet of the
// IP address.
func shortLabel(r deviceResult) string {
	if r.Hostname != "" {
		h := r.Hostname
		if len([]rune(h)) > 14 {
			h = string([]rune(h)[:14]) + "…"
		}
		return html.EscapeString(h)
	}
	parts := strings.Split(r.IP, ".")
	if len(parts) == 4 {
		return "." + parts[3]
	}
	return html.EscapeString(r.IP)
}

// nodeTooltip is the text a viewer gets on hover. On a crowded map the
// per-node caption has to go, so this carries what the caption used to say
// and more — the map stops trying to print everything at once.
func nodeTooltip(r deviceResult) string {
	parts := []string{r.IP}
	if r.Hostname != "" {
		parts = append(parts, r.Hostname)
	}
	if r.ProbableType != "" {
		parts = append(parts, r.ProbableType)
	}
	if r.MAC != "" {
		parts = append(parts, "MAC "+r.MAC)
	}
	parts = append(parts, riskLabel[r.Risk])
	if r.Isolated {
		parts = append(parts, fmt.Sprintf("isolado · %d pacotes bloqueados", r.BlockedPackets))
	}
	return html.EscapeString(strings.Join(parts, " · "))
}

// nodeOpen starts a device's group in the map. The data attributes are
// what the page's script hangs on: data-ip ties the node to its card in
// the list, so a click can bring up that card's buttons, and data-busca
// is the same search text the card carries, so the search box can dim
// the nodes that do not match.
func nodeOpen(r deviceResult) string {
	return fmt.Sprintf(`<g class="node" data-ip="%s" data-busca="%s" tabindex="0" role="button" aria-label="%s"><title>%s</title>`,
		html.EscapeString(r.IP), searchText(r), nodeTooltip(r), nodeTooltip(r))
}

// The nodes sit on an arc below the router (15° to 165° from the x axis —
// in screen coordinates that runs from the bottom-right corner to the
// bottom-left one, through "straight down"), spread over concentric rings:
// each ring takes only as many nodes as fit along its arc, and the
// overflow goes to the next ring out.
//
// The layout has two shapes because one shape cannot serve both sizes. A
// small network gets roomy nodes with a caption under each. Past a few
// dozen devices the captions collide and, worse, a line from every node
// back to the router turns into a grey fan that buries the data — so the
// crowded layout drops both: the rings themselves are drawn as faint arcs,
// which says "these orbit the router" with six strokes instead of a
// hundred and thirty, and identity moves to the hover tooltip.
const compactThreshold = 28

type mapLayout struct {
	baseRadius float64
	nodeRadius float64
	spacing    float64 // arc length reserved per node
	ringStep   float64
	labels     bool
}

func layoutFor(count int) mapLayout {
	if count > compactThreshold {
		// tighter first ring too: with six rings to draw, a wide gap
		// between the router and the innermost one is just dead space
		return mapLayout{baseRadius: 112, nodeRadius: 13, spacing: 34, ringStep: 54, labels: false}
	}
	return mapLayout{baseRadius: 160, nodeRadius: 22, spacing: 62, ringStep: 96, labels: true}
}

const (
	startAngle = 15.0
	endAngle   = 165.0
)

type nodePosition struct{ radius, angle float64 }

// nodePositions returns the radius and angle of each of the n nodes,
// filling one ring at a time from the inside out.
func nodePositions(n int, l mapLayout) []nodePosition {
	const spread = (endAngle - startAngle) * math.Pi / 180
	positions := make([]nodePosition, 0, n)
	for ring := 0; len(positions) < n; ring++ {
		radius := l.baseRadius + float64(ring)*l.ringStep
		capacity := int(radius*spread/l.spacing) + 1
		fit := capacity
		if left := n - len(positions); left < fit {
			fit = left
		}

		// a partial last ring keeps the spacing of a full one and is
		// centred on "straight down", instead of being stretched to the
		// two extremes — three leftover devices spread across the whole
		// arc read as an outer ring that is mostly empty, and it forces
		// the canvas to reserve height nothing occupies
		first, last := startAngle, endAngle
		if fit < capacity && fit > 1 {
			used := (endAngle - startAngle) * float64(fit-1) / float64(capacity-1)
			first, last = 90-used/2, 90+used/2
		}

		for i := 0; i < fit; i++ {
			degrees := 90.0
			if fit > 1 {
				degrees = first + (last-first)*float64(i)/float64(fit-1)
			}
			positions = append(positions, nodePosition{radius, degrees * math.Pi / 180})
		}
	}
	return positions
}

// ringArc draws the hairline that stands in for the spokes.
func ringArc(svg *strings.Builder, cx, cy, radius float64) {
	rad := math.Pi / 180
	x1, y1 := cx+radius*math.Cos(startAngle*rad), cy+radius*math.Sin(startAngle*rad)
	x2, y2 := cx+radius*math.Cos(endAngle*rad), cy+radius*math.Sin(endAngle*rad)
	fmt.Fprintf(svg, `<path d="M %.1f %.1f A %.1f %.1f 0 0 1 %.1f %.1f" fill="none" stroke="var(--grid)" stroke-width="1"/>`,
		x1, y1, radius, radius, x2, y2)
}

// networkMapSVG draws the laptop, the router and the devices found as a
// visual map: ordinary devices on rings around the router, isolated ones
// pulled aside into a quarantine zone with no line back to the router,
// only to the laptop — which is what intercepts their traffic through ARP
// spoofing.
func networkMapSVG(network *networkInfo, results []deviceResult) string {
	const gwY = 150
	const nbX, nbY = 74, 52

	var ordinary, isolated []deviceResult
	remote := 0
	for _, r := range results {
		// the map is drawn around this machine's router, so devices
		// reported by an agent in another subnet have no meaningful place
		// in it — they hang off a different router entirely. They are
		// counted here and listed as cards below the map instead.
		if r.Agent != "" {
			remote++
			continue
		}
		if r.Isolated {
			isolated = append(isolated, r)
		} else {
			ordinary = append(ordinary, r)
		}
	}

	l := layoutFor(len(ordinary))
	positions := nodePositions(len(ordinary), l)

	// size the canvas to where the nodes actually landed, not to the
	// outermost ring's full extent: the last ring is usually partial, so
	// reserving a whole ring's height leaves a band of dead space below
	maxRadius, reachX, reachY := l.baseRadius, l.baseRadius, 0.0
	for _, p := range positions {
		maxRadius = math.Max(maxRadius, p.radius)
		reachX = math.Max(reachX, math.Abs(p.radius*math.Cos(p.angle)))
		reachY = math.Max(reachY, p.radius*math.Sin(p.angle))
	}
	bottomPad := 56.0
	if l.labels {
		bottomPad = 78
	}
	width := int(math.Max(820, 2*(reachX+l.nodeRadius+46)))
	height := int(gwY + reachY + l.nodeRadius + bottomPad)
	gwX := float64(width) / 2

	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Mapa da rede" style="width:100%%;height:auto;display:block;font-family:inherit;">`, width, height)

	// the rings first, so everything else sits on top of them
	for ring := 0; ; ring++ {
		radius := l.baseRadius + float64(ring)*l.ringStep
		if radius > maxRadius+0.1 {
			break
		}
		ringArc(&svg, gwX, gwY, radius)
	}

	// the laptop (ImmuneGate itself) and its link to the router
	fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%.1f" y2="%d" stroke="var(--accent)" stroke-width="1.5"/>`, nbX, nbY, gwX, gwY)
	fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="19" fill="var(--accent)"/><text x="%d" y="%d" text-anchor="middle" font-size="15">🛡️</text><text x="%d" y="%d" text-anchor="middle" font-size="11" fill="var(--ink-2)">ImmuneGate</text>`,
		nbX, nbY, nbX, nbY+5, nbX, nbY+34)

	// the router
	fmt.Fprintf(&svg, `<circle cx="%.1f" cy="%d" r="22" fill="var(--router)"/><text x="%.1f" y="%d" text-anchor="middle" font-size="17">📶</text><text x="%.1f" y="%d" text-anchor="middle" font-size="11" fill="var(--ink-2)">%s</text>`,
		gwX, gwY, gwX, gwY+6, gwX, gwY+40, html.EscapeString(network.Gateway.String()))

	// ordinary devices, on rings around the router
	for i, r := range ordinary {
		p := positions[i]
		x := gwX + p.radius*math.Cos(p.angle)
		y := float64(gwY) + p.radius*math.Sin(p.angle)
		svg.WriteString(nodeOpen(r))
		fmt.Fprintf(&svg, `<circle cx="%.1f" cy="%.1f" r="%.0f" fill="var(--risk-%s)" stroke="var(--surface)" stroke-width="2"/>`,
			x, y, l.nodeRadius, riskSlug[r.Risk])
		fmt.Fprintf(&svg, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="%.0f">%s</text>`,
			x, y+l.nodeRadius*0.33, l.nodeRadius*0.85, typeIcon(r.ProbableType))
		if l.labels {
			fmt.Fprintf(&svg, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="10" fill="var(--ink-2)">%s</text>`,
				x, y+l.nodeRadius+14, shortLabel(r))
		}
		svg.WriteString(`</g>`)
	}

	// quarantine zone — no link to the router, only to the laptop, making
	// it visually obvious that it was cut off from the main network
	if len(isolated) > 0 {
		rows := (len(isolated) + 1) / 2
		qw := 210.0
		qx, qy := float64(width)-qw-18, 16.0
		qh := float64(62 + rows*66)
		fmt.Fprintf(&svg, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="10" fill="var(--quarantine-bg)" stroke="var(--risk-alto)" stroke-width="1" stroke-dasharray="5,4"/>`, qx, qy, qw, qh)
		fmt.Fprintf(&svg, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="12" fill="var(--risk-alto)" font-weight="600">🚧 Quarentena</text>`, qx+qw/2, qy+22)
		// one dashed link to the box, not one per node: the point is that
		// the zone hangs off the laptop rather than the router, and
		// repeating that per device drew long lines across the whole map
		fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%.1f" y2="%.1f" stroke="var(--risk-alto)" stroke-width="1" stroke-dasharray="4,4" opacity="0.45"/>`, nbX, nbY, qx, qy+qh/2)

		for i, r := range isolated {
			x := qx + 56 + float64(i%2)*98
			y := qy + 56 + float64(i/2)*66
			svg.WriteString(nodeOpen(r))
			fmt.Fprintf(&svg, `<circle cx="%.1f" cy="%.1f" r="17" fill="var(--risk-alto)" stroke="var(--surface)" stroke-width="2"/><text x="%.1f" y="%.1f" text-anchor="middle" font-size="13">🔒</text>`, x, y, x, y+5)
			fmt.Fprintf(&svg, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="10" fill="var(--ink-2)">%s</text>`, x, y+30, shortLabel(r))
			fmt.Fprintf(&svg, `<text x="%.1f" y="%.1f" text-anchor="middle" font-size="9" fill="var(--ink-3)">🚫 %d</text></g>`, x, y+42, r.BlockedPackets)
		}
	}

	if remote > 0 {
		fmt.Fprintf(&svg, `<text x="18" y="%d" font-size="11" fill="var(--ink-3)">🛰️ mais %d dispositivo(s) em outras sub-redes, reportados por agentes — listados abaixo</text>`,
			height-16, remote)
	}
	if !l.labels {
		fmt.Fprintf(&svg, `<text x="18" y="%d" font-size="11" fill="var(--ink-3)">Rede grande: passe o cursor sobre um ponto para ver de quem é.</text>`, height-34)
	}

	svg.WriteString(`</svg>`)
	return svg.String()
}
