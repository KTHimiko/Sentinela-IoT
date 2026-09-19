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

// Geometry of the nodes around the router. They sit on an arc below it
// (15° to 165°, measured from the x axis — in screen coordinates that
// spans from the bottom-right corner to the bottom-left one, passing
// through "straight down"), spread over concentric rings: each ring takes
// only as many nodes as fit along its arc without the circles touching,
// and the overflow goes to the next ring out. With a single fixed-radius
// ring, any network with more than about nine devices turned into a blob
// of circles stacked on top of each other.
const (
	baseRadius  = 190.0
	ringStep    = 100.0
	nodeSpacing = 64.0 // circle diameter (48) plus room for the label not to touch its neighbour
	startAngle  = 15.0
	endAngle    = 165.0
)

type nodePosition struct{ radius, angle float64 }

// nodePositions returns the radius and angle of each of the n nodes,
// filling one ring at a time from the inside out.
func nodePositions(n int) []nodePosition {
	const spread = (endAngle - startAngle) * math.Pi / 180
	positions := make([]nodePosition, 0, n)
	for ring := 0; len(positions) < n; ring++ {
		radius := baseRadius + float64(ring)*ringStep
		fit := int(radius*spread/nodeSpacing) + 1
		if left := n - len(positions); left < fit {
			fit = left // last ring: spread only what is left
		}
		for i := 0; i < fit; i++ {
			degrees := 90.0
			if fit > 1 {
				degrees = startAngle + (endAngle-startAngle)*float64(i)/float64(fit-1)
			}
			positions = append(positions, nodePosition{radius, degrees * math.Pi / 180})
		}
	}
	return positions
}

// networkMapSVG draws the laptop, the router and the devices found as a
// visual map: ordinary devices on rings around the router, isolated ones
// pulled aside into a "quarantine zone" with no line back to the router,
// only to the laptop — which is what intercepts their traffic through ARP
// spoofing.
func networkMapSVG(network *networkInfo, results []deviceResult) string {
	const gwY = 190
	const nbX, nbY = 90, 60

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

	// the canvas grows with the outermost ring instead of being fixed
	positions := nodePositions(len(ordinary))
	maxRadius := baseRadius
	if len(positions) > 0 {
		maxRadius = positions[len(positions)-1].radius
	}
	width := int(math.Max(900, 2*(maxRadius+90)))
	height := int(gwY + maxRadius + 110)
	gwX := width / 2

	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" style="width:100%%;height:auto;background:#fafafa;border-radius:8px;font-family:-apple-system,Segoe UI,Arial,sans-serif;">`, width, height)

	// the laptop (Sentinela IoT itself)
	fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#9575cd" stroke-width="2"/>`, nbX, nbY, gwX, gwY)
	fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="26" fill="#5e35b1"/><text x="%d" y="%d" text-anchor="middle" font-size="20">🛡️</text><text x="%d" y="%d" text-anchor="middle" font-size="11" fill="#333">Sentinela IoT</text>`,
		nbX, nbY, nbX, nbY+7, nbX, nbY+42)

	// the router
	fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="30" fill="#1565c0"/><text x="%d" y="%d" text-anchor="middle" font-size="22">📶</text><text x="%d" y="%d" text-anchor="middle" font-size="12" fill="#333">Roteador (%s)</text>`,
		gwX, gwY, gwX, gwY+8, gwX, gwY+50, html.EscapeString(network.Gateway.String()))

	// ordinary devices, on rings around the router
	for i, r := range ordinary {
		p := positions[i]
		x := gwX + int(p.radius*math.Cos(p.angle))
		y := gwY + int(p.radius*math.Sin(p.angle))
		color := riskColor[r.Risk]
		fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#bbb" stroke-width="2"/>`, gwX, gwY, x, y)
		fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="24" fill="%s"/><text x="%d" y="%d" text-anchor="middle" font-size="18">%s</text><text x="%d" y="%d" text-anchor="middle" font-size="10" fill="#333">%s</text>`,
			x, y, color, x, y+6, typeIcon(r.ProbableType), x, y+40, shortLabel(r))
	}

	// quarantine zone — no link to the router, only to the laptop, making
	// it visually obvious that it was cut off from the main network
	if len(isolated) > 0 {
		// top-right corner: the arc of ordinary devices occupies the
		// bottom half, so this is the only area it never collides with,
		// however many rings there are
		rows := (len(isolated) + 1) / 2
		qx, qy, qw := width-250, 20, 220
		qh := 70 + rows*75
		fmt.Fprintf(&svg, `<rect x="%d" y="%d" width="%d" height="%d" rx="12" fill="#fdecea" stroke="#c62828" stroke-width="2" stroke-dasharray="6,4"/>`, qx, qy, qw, qh)
		fmt.Fprintf(&svg, `<text x="%d" y="%d" text-anchor="middle" font-size="13" fill="#c62828" font-weight="bold">🚧 Zona de quarentena</text>`, qx+qw/2, qy+24)

		for i, r := range isolated {
			x := qx + 50 + (i%2)*95
			y := qy + 65 + (i/2)*75
			fmt.Fprintf(&svg, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#c62828" stroke-width="2" stroke-dasharray="4,3"/>`, nbX, nbY, x, y)
			fmt.Fprintf(&svg, `<circle cx="%d" cy="%d" r="22" fill="#b3261e"/><text x="%d" y="%d" text-anchor="middle" font-size="16">🔒</text><text x="%d" y="%d" text-anchor="middle" font-size="9" fill="#333">%s</text><text x="%d" y="%d" text-anchor="middle" font-size="9" fill="#c62828">🚫 %d</text>`,
				x, y, x, y+5, x, y+36, shortLabel(r), x, y+48, r.BlockedPackets)
		}
	}

	if remote > 0 {
		fmt.Fprintf(&svg, `<text x="20" y="%d" font-size="12" fill="#5e35b1">🛰️ mais %d dispositivo(s) em outras sub-redes, reportados por agentes — veja os cartões abaixo</text>`,
			height-20, remote)
	}

	svg.WriteString(`</svg>`)
	return svg.String()
}
