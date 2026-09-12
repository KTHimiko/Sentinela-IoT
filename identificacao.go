package main

import (
	"context"
	"net"
	"strings"
	"time"
)

// ---------- identificação do tipo de dispositivo ----------

// tabelaOUI mapeia os 3 primeiros bytes do MAC (o "OUI", registrado
// junto ao IEEE) pro fabricante da placa de rede. Não é uma lista
// completa (a IEEE registra dezenas de milhares de blocos) — cobre só
// fabricantes comuns em casas/pequenas empresas, o suficiente pra dar
// um palpite razoável no dashboard.
type fabricanteInfo struct {
	fabricante string
	tipo       string
}

var tabelaOUI = map[string]fabricanteInfo{
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

// identificarPorMAC procura o OUI (3 primeiros bytes) do MAC na tabela
// e devolve o fabricante e um palpite de tipo de dispositivo. Se o MAC
// não estiver na tabela (o caso mais comum, já que a lista é pequena),
// devolve "Desconhecido" em vez de travar ou mentir uma classificação.
func identificarPorMAC(mac string) (fabricante, tipo string) {
	if len(mac) < 8 {
		return "", ""
	}
	oui := strings.ToUpper(mac[:8])
	if info, ok := tabelaOUI[oui]; ok {
		return info.fabricante, info.tipo
	}
	return "Desconhecido", ""
}

// resolverHostname tenta descobrir o nome que o próprio dispositivo
// anuncia na rede (reverse DNS/mDNS via resolver do sistema — muitos
// roteadores registram o hostname que o dispositivo pede via DHCP,
// tipo "iPhone-de-Maria" ou "DESKTOP-AB12CD"). Usa um timeout curto
// pra não travar a varredura inteira num dispositivo que não responde.
func resolverHostname(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	nomes, err := (&net.Resolver{}).LookupAddr(ctx, ip)
	if err != nil || len(nomes) == 0 {
		return ""
	}
	return strings.TrimSuffix(nomes[0], ".")
}

// refinarTipoPorHostname procura palavras-chave comuns no hostname.
// O hostname é um sinal mais específico que o fabricante do MAC (ex:
// "iPhone-de-Luan" via Apple já cai no palpite certo, mas "DESKTOP-X1"
// não teria como vir só do OUI), então tem prioridade sobre o OUI
// quando bate com alguma palavra-chave conhecida.
func refinarTipoPorHostname(hostname string) string {
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
