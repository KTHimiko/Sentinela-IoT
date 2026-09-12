package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ---------- segurança do próprio Wi-Fi ----------

// Tudo que construímos até aqui olha os dispositivos dentro da LAN —
// mas o rádio Wi-Fi em si é uma outra superfície de ataque: uma rede
// falsa imitando a sua (evil twin) ou uma criptografia fraca no
// próprio roteador nunca apareceriam em nenhuma varredura de host.
// Usamos o nmcli (já vem com o NetworkManager, que é o padrão na
// maioria das distros desktop) pra enxergar isso.
type redeWifiVisivel struct {
	ativa, ssid, bssid, seguranca string
}

// listarRedesWifi lê `nmcli -t -f active,ssid,bssid,security dev
// wifi`. No modo terse (-t) o nmcli separa campos com ":", mas o
// próprio BSSID também usa ":" — o nmcli escapa isso como "\:", então
// protegemos essa sequência antes de separar os campos e desfazemos
// depois.
func listarRedesWifi() []redeWifiVisivel {
	exec.Command("nmcli", "dev", "wifi", "rescan").Run() // melhor esforço, ignora erro
	time.Sleep(2 * time.Second)

	saida, err := exec.Command("nmcli", "-t", "-f", "active,ssid,bssid,security", "dev", "wifi").Output()
	if err != nil {
		return nil
	}

	var redes []redeWifiVisivel
	for _, linha := range strings.Split(strings.TrimSpace(string(saida)), "\n") {
		if linha == "" {
			continue
		}
		protegida := strings.ReplaceAll(linha, `\:`, "\x00")
		campos := strings.SplitN(protegida, ":", 4)
		if len(campos) < 4 {
			continue
		}
		desescapar := func(s string) string { return strings.ReplaceAll(s, "\x00", ":") }
		redes = append(redes, redeWifiVisivel{
			ativa:     desescapar(campos[0]),
			ssid:      desescapar(campos[1]),
			bssid:     desescapar(campos[2]),
			seguranca: desescapar(campos[3]),
		})
	}
	return redes
}

// avaliarSegurancaWifi classifica o texto de segurança que o nmcli
// devolve (ex: "WPA1 WPA2", "WEP", "--" pra rede aberta).
func avaliarSegurancaWifi(seguranca string) (risco, motivo string) {
	switch {
	case seguranca == "" || seguranca == "--":
		return "alto", "Rede Wi-Fi sem senha (aberta) — qualquer um por perto pode entrar e ver seu tráfego."
	case strings.Contains(seguranca, "WEP"):
		return "alto", "Rede Wi-Fi protegida por WEP, um protocolo quebrado há mais de 15 anos — pode ser invadida em minutos."
	case strings.Contains(seguranca, "WPA3"):
		return "baixo", "Rede Wi-Fi protegida por WPA3, o padrão mais atual."
	case strings.Contains(seguranca, "WPA2"):
		return "baixo", "Rede Wi-Fi protegida por WPA2 — adequado pro uso doméstico."
	case strings.Contains(seguranca, "WPA"):
		return "médio", "Rede Wi-Fi protegida só por WPA1, considerado fraco hoje em dia — o ideal é migrar pra WPA2 ou WPA3 nas configurações do roteador."
	default:
		return "", fmt.Sprintf("Tipo de segurança do Wi-Fi não reconhecido pelo programa (%s).", seguranca)
	}
}

var wifiSegurancaMu sync.RWMutex
var wifiSegurancaAtual struct {
	SSID, Protocolo, Risco, Motivo string
	UltimaChecagem                 time.Time
}

func verificarSegurancaWifi(redes []redeWifiVisivel) {
	for _, r := range redes {
		if r.ativa != "sim" {
			continue
		}
		risco, motivo := avaliarSegurancaWifi(r.seguranca)
		wifiSegurancaMu.Lock()
		wifiSegurancaAtual.SSID = r.ssid
		wifiSegurancaAtual.Protocolo = r.seguranca
		wifiSegurancaAtual.Risco = risco
		wifiSegurancaAtual.Motivo = motivo
		wifiSegurancaAtual.UltimaChecagem = time.Now()
		wifiSegurancaMu.Unlock()
		return
	}
}

func lerCacheWifi() (ssid, protocolo, risco, motivo string, ultimaChecagem time.Time) {
	wifiSegurancaMu.RLock()
	defer wifiSegurancaMu.RUnlock()
	i := wifiSegurancaAtual
	return i.SSID, i.Protocolo, i.Risco, i.Motivo, i.UltimaChecagem
}

// evilTwinMu/evilTwinAlertados evitam alertar de novo, a cada ciclo,
// pro mesmo BSSID impostor — só na primeira vez que ele aparece.
var evilTwinMu sync.Mutex
var evilTwinAlertados = make(map[string]bool)

// verificarEvilTwin procura, entre as redes visíveis, alguma com o
// MESMO nome (SSID) da rede que o notebook está usando, mas ABERTA
// (sem senha) enquanto a rede de verdade é protegida. Roteadores
// domésticos com Wi-Fi dupla banda costumam anunciar o mesmo SSID com
// BSDDIs diferentes e a MESMA segurança (por isso não alertamos só por
// "SSID igual, BSSID diferente" — isso sozinho é normal demais e daria
// falso positivo o tempo todo); uma cópia sem senha da sua rede
// protegida é um sinal bem mais específico de ataque evil twin.
func verificarEvilTwin(redes []redeWifiVisivel) {
	var atual *redeWifiVisivel
	for i := range redes {
		if redes[i].ativa == "sim" {
			atual = &redes[i]
			break
		}
	}
	if atual == nil || atual.ssid == "" {
		return // não conectado por Wi-Fi (ex: rede cabeada) — nada a checar
	}
	protegida := atual.seguranca != "" && atual.seguranca != "--"
	if !protegida {
		return
	}

	for _, r := range redes {
		if r.bssid == atual.bssid || r.ssid != atual.ssid {
			continue
		}
		if r.seguranca != "" && r.seguranca != "--" {
			continue // também protegida, provavelmente só a outra banda do mesmo roteador
		}

		evilTwinMu.Lock()
		jaAlertado := evilTwinAlertados[r.bssid]
		evilTwinAlertados[r.bssid] = true
		evilTwinMu.Unlock()
		if jaAlertado {
			continue
		}

		registrarEvento("alerta_evil_twin", r.bssid, fmt.Sprintf(
			"Um ponto de acesso SEM SENHA está anunciando o mesmo nome (%q) da sua rede Wi-Fi, que normalmente é protegida por %s — pode ser um ataque de rede falsa (evil twin) tentando roubar sua conexão.",
			atual.ssid, atual.seguranca))
	}
}

// iniciarVerificacaoWifi roda em segundo plano, reaproveitando a mesma
// lista de redes visíveis pras duas checagens (evita mandar dois
// rescans separados por ciclo).
func iniciarVerificacaoWifi() {
	go func() {
		for {
			redes := listarRedesWifi()
			verificarSegurancaWifi(redes)
			verificarEvilTwin(redes)
			time.Sleep(2 * time.Minute)
		}
	}()
}
