package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

// ---------- device type identification ----------

// ouiTable maps the first 3 bytes of a MAC (the "OUI", registered with
// the IEEE) to the vendor of the network card. It is not a complete list
// — the IEEE registers tens of thousands of blocks — it only covers
// vendors common in homes and small businesses, which is enough for a
// reasonable guess in the dashboard.
type vendorInfo struct {
	vendor     string
	deviceType string
}

var ouiTable = map[string]vendorInfo{
	// notebooks/PCs
	"00:1B:21": {"Intel Corporate", "💻 Computador (PC/notebook)"},
	"3C:97:0E": {"Intel Corporate", "💻 Computador (PC/notebook)"},
	"A4:34:D9": {"Intel Corporate", "💻 Computador (PC/notebook)"},
	"00:14:22": {"Dell Inc.", "💻 Computador (PC/notebook)"},
	"D4:BE:D9": {"Dell Inc.", "💻 Computador (PC/notebook)"},
	"F8:B1:56": {"Dell Inc.", "💻 Computador (PC/notebook)"},
	"04:D9:F5": {"ASUSTek Computer", "💻 Computador (PC/notebook)"},
	"AC:9E:17": {"ASUSTek Computer", "💻 Computador (PC/notebook)"},
	"00:23:24": {"Lenovo", "💻 Computador (PC/notebook)"},
	"3C:D9:2B": {"HP Inc.", "💻 Computador (PC/notebook)"},

	// Apple (Mac, iPhone, iPad — a Apple registra centenas de blocos,
	// isso cobre só alguns comuns)
	"00:1C:B3": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},
	"AC:DE:48": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},
	"F0:18:98": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},
	"3C:15:C2": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},
	"A4:5E:60": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},
	"00:23:DF": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},
	"28:CF:E9": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},
	"DC:A9:04": {"Apple", "🍎 Dispositivo Apple (Mac/iPhone/iPad)"},

	// celulares Android
	"5C:0A:5B": {"Samsung Electronics", "📱 Celular/tablet"},
	"D0:22:BE": {"Samsung Electronics", "📱 Celular/tablet"},
	"78:11:DC": {"Xiaomi Communications", "📱 Celular/tablet"},
	"34:CE:00": {"Xiaomi Communications", "📱 Celular/tablet"},
	"64:B4:73": {"Xiaomi Communications", "📱 Celular/tablet"},
	"F4:9F:F3": {"Huawei Technologies", "📱 Celular/tablet"},
	"00:E0:FC": {"Huawei Technologies", "📱 Celular/tablet"},

	// dispositivos IoT (lâmpadas, tomadas, sensores — costumam usar
	// módulos Espressif ESP8266/ESP32 por baixo, seja qual for a marca
	// vendida na caixa)
	"24:6F:28": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"30:AE:A4": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"3C:71:BF": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"5C:CF:7F": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"A4:CF:12": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"CC:50:E3": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"DC:4F:22": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"EC:FA:BC": {"Espressif Inc.", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"EC:B5:FA": {"Signify/Philips Hue", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"00:17:88": {"Signify/Philips Hue", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"D0:73:D5": {"LIFX", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"94:10:3E": {"Belkin (Wemo)", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},
	"18:B4:30": {"Nest Labs", "💡 Dispositivo IoT (lâmpada/tomada/sensor inteligente)"},

	// assistentes virtuais / streaming
	"44:65:0D": {"Amazon Technologies", "🔊 Assistente virtual / streaming (Alexa/Echo)"},
	"68:37:E9": {"Amazon Technologies", "🔊 Assistente virtual / streaming (Alexa/Echo)"},
	"FC:65:DE": {"Amazon Technologies", "🔊 Assistente virtual / streaming (Alexa/Echo)"},
	"F4:F5:D8": {"Google Inc.", "🔊 Assistente virtual / streaming (Google/Chromecast)"},
	"54:60:09": {"Google Inc.", "🔊 Assistente virtual / streaming (Google/Chromecast)"},
	"A4:77:33": {"Google Inc.", "🔊 Assistente virtual / streaming (Google/Chromecast)"},
	"B0:A7:37": {"Roku", "🔊 Assistente virtual / streaming"},

	// infraestrutura de rede (não deveriam ser "isolados" como se
	// fossem dispositivos finais)
	"00:1B:11": {"D-Link", "📶 Equipamento de rede (roteador/AP)"},
	"A0:40:A0": {"Netgear", "📶 Equipamento de rede (roteador/AP)"},
	"24:A4:3C": {"Ubiquiti Networks", "📶 Equipamento de rede (roteador/AP)"},
	"04:18:D6": {"Ubiquiti Networks", "📶 Equipamento de rede (roteador/AP)"},
	"50:C7:BF": {"TP-Link", "📶 Equipamento de rede (roteador/AP)"},
	"EC:08:6B": {"TP-Link", "📶 Equipamento de rede (roteador/AP)"},
	"98:DA:C4": {"TP-Link", "📶 Equipamento de rede (roteador/AP)"},

	// Raspberry Pi (comum tanto como "servidor caseiro" quanto como
	// controlador de projetos IoT)
	"B8:27:EB": {"Raspberry Pi Foundation", "🍓 Raspberry Pi / placa de projeto"},
	"DC:A6:32": {"Raspberry Pi Foundation", "🍓 Raspberry Pi / placa de projeto"},
	"E4:5F:01": {"Raspberry Pi Foundation", "🍓 Raspberry Pi / placa de projeto"},

	// máquinas virtuais (útil pra não confundir uma VM de teste com um
	// dispositivo físico de verdade)
	"00:0C:29": {"VMware", "🖥️ Máquina virtual"},
	"00:50:56": {"VMware", "🖥️ Máquina virtual"},
	"08:00:27": {"Oracle VirtualBox", "🖥️ Máquina virtual"},
}

// lookupByMAC looks the OUI (first 3 bytes) of the MAC up in the table
// and returns the vendor plus a guess at the device type. When the MAC is
// not in the table — the common case, since the list is small — it
// returns "Desconhecido" instead of failing or inventing a classification.
func lookupByMAC(mac string) (vendor, deviceType string) {
	if len(mac) < 8 {
		return "", ""
	}
	oui := strings.ToUpper(mac[:8])
	if info, ok := ouiTable[oui]; ok {
		return info.vendor, info.deviceType
	}
	return "Desconhecido", ""
}

// resolveHostname tries to find the name the device announces on the
// network (reverse DNS/mDNS through the system resolver — many routers
// register the hostname the device asks for over DHCP, like
// "iPhone-de-Maria" or "DESKTOP-AB12CD"). It uses a short timeout so one
// unresponsive device cannot stall the whole scan.
func resolveHostname(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	names, err := (&net.Resolver{}).LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// refineTypeByHostname looks for common keywords in the hostname. The
// hostname is a more specific signal than the MAC vendor ("iPhone-de-Luan"
// under Apple already lands on the right guess, but "DESKTOP-X1" could
// never come from the OUI alone), so it takes priority over the OUI
// whenever it matches a known keyword.
func refineTypeByHostname(hostname string) string {
	h := strings.ToLower(hostname)
	switch {
	case h == "":
		return ""
	case strings.Contains(h, "iphone") || strings.Contains(h, "android") || strings.Contains(h, "galaxy") || strings.Contains(h, "redmi"):
		return "📱 Celular/tablet"
	case strings.Contains(h, "desktop") || strings.Contains(h, "notebook") || strings.Contains(h, "laptop") || strings.Contains(h, "pc-"):
		return "💻 Computador (PC/notebook)"
	case strings.Contains(h, "printer") || strings.Contains(h, "impressora"):
		return "🖨️ Impressora"
	case strings.Contains(h, "smarttv") || strings.Contains(h, "smart-tv") || strings.Contains(h, "bravia") || strings.Contains(h, "roku"):
		return "📺 Smart TV"
	case strings.Contains(h, "echo") || strings.Contains(h, "alexa") || strings.Contains(h, "google-home") || strings.Contains(h, "chromecast"):
		return "🔊 Assistente virtual / streaming"
	case strings.Contains(h, "cam") || strings.Contains(h, "camera"):
		return "🎥 Câmera IP"
	default:
		return ""
	}
}

// isRandomizedMAC reports whether the MAC has the "locally administered"
// bit set (the second least significant bit of the first octet) and the
// multicast bit clear. Modern phones and laptops (iOS, Android, Windows,
// Linux) rotate their MAC per Wi-Fi network as a privacy feature, and
// those MACs always follow this pattern. Since a randomized MAC can never
// match the OUI table — the block is not registered with the IEEE — this
// check recovers a whole class of devices that would otherwise stay
// forever as "type not identified".
func isRandomizedMAC(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	first, err := strconv.ParseUint(mac[0:2], 16, 8)
	if err != nil {
		return false
	}
	b := byte(first)
	const localBit = 0x02     // locally administered
	const multicastBit = 0x01 // group address (not a single device)
	return b&localBit != 0 && b&multicastBit == 0
}

// inferTypeByPorts guesses a device type from the services it leaves
// open, used only as a last resort when OUI, hostname, mDNS and SSDP said
// nothing. Ports are a functional signal (what the device does), not a
// vendor one, so the rules go from most specific to most generic and stop
// at the first match.
func inferTypeByPorts(ports []string) string {
	has := make(map[string]bool, len(ports))
	for _, p := range ports {
		has[p] = true
	}
	switch {
	case has["9100"]:
		return "🖨️ Impressora"
	case has["554"]:
		return "🎥 Câmera IP"
	case has["445"] || has["3389"]:
		return "💻 Computador (provável Windows)"
	case has["3306"] || has["5432"]:
		return "🗄️ Servidor de banco de dados"
	case has["23"]:
		return "💡 Dispositivo IoT (Telnet aberto — comum em equipamento embarcado)"
	case has["22"] && !has["80"] && !has["443"]:
		return "🖥️ Servidor/dispositivo com acesso SSH"
	default:
		return ""
	}
}
