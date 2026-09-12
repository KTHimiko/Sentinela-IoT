package main

import (
	"fmt"
	"sync"
	"time"
)

// ---------- monitoramento contínuo ----------

// estadoMu protege o resultado da última varredura, que fica em cache
// e é servido a quem abrir o dashboard — em vez de escanear a rede do
// zero a cada carregamento de página, que é lento e não é como um NOC
// de verdade funciona (ele observa continuamente, não sob demanda).
var estadoMu sync.RWMutex
var ultimosResultados []resultadoDispositivo
var ultimaAtualizacao time.Time

func atualizarCache(rede *infoRede) []resultadoDispositivo {
	atuais := escanear(rede)
	estadoMu.Lock()
	ultimosResultados = atuais
	ultimaAtualizacao = time.Now()
	estadoMu.Unlock()
	return atuais
}

func lerCache() ([]resultadoDispositivo, time.Time) {
	estadoMu.RLock()
	defer estadoMu.RUnlock()
	return ultimosResultados, ultimaAtualizacao
}

func porIP(rs []resultadoDispositivo) map[string]resultadoDispositivo {
	mapa := make(map[string]resultadoDispositivo, len(rs))
	for _, r := range rs {
		mapa[r.IP] = r
	}
	return mapa
}

// detectarMudancas compara a varredura anterior com a atual e registra
// no histórico o que mudou: dispositivo novo, dispositivo que sumiu ou
// risco que mudou. Isolamento/reconexão são registrados direto onde
// acontecem (isolarDispositivo/reconectarDispositivo), não aqui.
// candidatosEvasao guarda, por fabricante, quando um dispositivo que
// estava isolado saiu da rede — pra comparar com dispositivos novos
// que aparecerem logo em seguida (ver detectarMudancas).
var evasaoMu sync.Mutex
var candidatosEvasao = make(map[string]time.Time)

const janelaEvasao = 3 * time.Minute

func detectarMudancas(anterior map[string]resultadoDispositivo, atuais []resultadoDispositivo) {
	// queda brusca no total de dispositivos ativos: mais provável ser
	// problema de Wi-Fi/roteador do que muitos aparelhos desligando ao
	// mesmo tempo, então merece um alerta próprio, além dos
	// "dispositivo_saiu" individuais que ainda serão registrados abaixo.
	totalAntes, totalDepois := len(anterior), len(atuais)
	if totalAntes >= 4 && totalDepois <= totalAntes/2 {
		registrarEvento("alerta_saude_rede", "", fmt.Sprintf(
			"O número de dispositivos ativos caiu de %d pra %d nessa varredura — verifique o Wi-Fi/roteador antes de assumir que são vários aparelhos desligados.", totalAntes, totalDepois))
	}

	vistos := make(map[string]bool, len(atuais))
	for _, r := range atuais {
		vistos[r.IP] = true
		antigo, existia := anterior[r.IP]
		if !existia {
			tipo := r.TipoProvavel
			if tipo == "" {
				tipo = "tipo não identificado"
			}
			// um dispositivo novo do mesmo fabricante que um outro que
			// saiu isolado há pouco tempo é suspeito de ser o mesmo
			// aparelho tentando escapar do bloqueio trocando de MAC/IP
			// (celulares modernos geram MAC aleatório por rede Wi-Fi).
			if r.Fabricante != "" && r.Fabricante != "Desconhecido" {
				evasaoMu.Lock()
				quando, suspeito := candidatosEvasao[r.Fabricante]
				evasaoMu.Unlock()
				if suspeito && time.Since(quando) < janelaEvasao {
					registrarEvento("alerta_evasao", r.IP, fmt.Sprintf(
						"Dispositivo novo do mesmo fabricante (%s) apareceu pouco depois de um dispositivo isolado sair da rede — pode ser o mesmo aparelho evitando o bloqueio ao trocar de MAC/IP.", r.Fabricante))
				}
			}
			registrarEvento("novo_dispositivo", r.IP, fmt.Sprintf("Apareceu na rede (%s)", tipo))
			continue
		}
		if antigo.Risco != r.Risco && !r.Confiavel {
			registrarEvento("mudanca_risco", r.IP, fmt.Sprintf("Risco mudou de %s pra %s", antigo.Risco, r.Risco))
		}
		// se o dispositivo ainda consta como isolado mas a regra de
		// firewall que confirmava isso sumiu, isso é uma falha séria de
		// contenção (iptables flushado manualmente, reinício do serviço
		// de firewall, etc.) — alerta uma vez, na transição.
		if r.Isolado && antigo.Isolado && antigo.BloqueioV4Ativo && !r.BloqueioV4Ativo {
			registrarEvento("alerta_bloqueio", r.IP, "O bloqueio IPv4 no iptables não está mais ativo, mas o dispositivo ainda consta como isolado — verifique manualmente!")
		}
		// o mesmo IP respondendo com um MAC diferente, sem o dispositivo
		// antigo ter saído da rede em nenhum momento (isso geraria um
		// "dispositivo_saiu" antes) — indica conflito de IP ou um ataque
		// de ARP spoofing mirando esse dispositivo específico, não o
		// gateway (que já é coberto por verificarSpoofingDoGateway).
		if antigo.MAC != "" && r.MAC != "" && antigo.MAC != r.MAC {
			registrarEvento("alerta_conflito_ip", r.IP, fmt.Sprintf(
				"O MAC que responde por esse IP mudou de %s pra %s sem o dispositivo antigo sair da rede — pode ser conflito de IP ou ARP spoofing mirando esse dispositivo.", antigo.MAC, r.MAC))
		}
		// porta que não estava aberta na varredura anterior e apareceu
		// agora — mais específico e acionável que só "risco mudou".
		antigoAbertas := make(map[string]bool, len(antigo.PortasNumeros))
		for _, p := range antigo.PortasNumeros {
			antigoAbertas[p] = true
		}
		for _, p := range r.PortasNumeros {
			if !antigoAbertas[p] {
				registrarEvento("porta_nova", r.IP, fmt.Sprintf("A porta %s abriu nesse dispositivo (não estava aberta na varredura anterior)", p))
			}
		}
	}
	for ip, r := range anterior {
		if vistos[ip] {
			continue
		}
		registrarEvento("dispositivo_saiu", ip, "Não respondeu mais na varredura (pode estar desligado ou ter saído da rede)")
		if r.Isolado && r.Fabricante != "" && r.Fabricante != "Desconhecido" {
			evasaoMu.Lock()
			candidatosEvasao[r.Fabricante] = time.Now()
			evasaoMu.Unlock()
		}
	}
}

// iniciarMonitoramentoContinuo roda a varredura em segundo plano num
// intervalo fixo, sem depender de alguém abrir o dashboard. É essa
// alça que transforma o projeto de "escâner sob demanda" em NOC.
func iniciarMonitoramentoContinuo(rede *infoRede, intervalo time.Duration) {
	go func() {
		primeiraVarredura := true
		var anterior map[string]resultadoDispositivo
		for {
			atuais := atualizarCache(rede)
			if !primeiraVarredura {
				detectarMudancas(anterior, atuais)
			}
			primeiraVarredura = false
			anterior = porIP(atuais)
			time.Sleep(intervalo)
		}
	}()
}
