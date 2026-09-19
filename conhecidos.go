package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- inventário de dispositivos já conhecidos ----------

// Sem memória de longo prazo, todo dispositivo que sai e volta à rede
// (celular em economia de energia, aparelho reiniciado, ou até uma
// varredura que não o alcançou por um ciclo) reaparece como se fosse
// "novo" — foi exatamente o ruído observado no histórico, com o mesmo
// aparelho registrado como novo várias vezes. O inventário guarda, em
// disco, cada MAC já visto, com quando apareceu pela primeira vez e a
// última vez que respondeu. Assim o monitoramento distingue um
// dispositivo genuinamente inédito (nunca visto) de um velho conhecido
// que apenas reapareceu — e essa memória sobrevive a reinícios do
// programa, como convém a um inventário de NAC.
const arquivoConhecidos = "conhecidos.json"

type dispositivoConhecido struct {
	MAC           string    `json:"mac"`
	PrimeiroVisto time.Time `json:"primeiro_visto"`
	UltimoVisto   time.Time `json:"ultimo_visto"`
	UltimoIP      string    `json:"ultimo_ip"`
}

var conhecidosMu sync.Mutex
var conhecidos = make(map[string]dispositivoConhecido) // chave: MAC em maiúsculas

func carregarConhecidos() {
	dados, err := os.ReadFile(arquivoConhecidos)
	if err != nil {
		return
	}
	var lista []dispositivoConhecido
	if json.Unmarshal(dados, &lista) != nil {
		return
	}
	conhecidosMu.Lock()
	for _, d := range lista {
		conhecidos[strings.ToUpper(d.MAC)] = d
	}
	conhecidosMu.Unlock()
}

func salvarConhecidos() {
	conhecidosMu.Lock()
	lista := make([]dispositivoConhecido, 0, len(conhecidos))
	for _, d := range conhecidos {
		lista = append(lista, d)
	}
	conhecidosMu.Unlock()

	dados, err := json.MarshalIndent(lista, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(arquivoConhecidos, dados, 0644)
}

// jaConhecido informa, sem alterar nada, se um MAC já foi visto em
// alguma varredura anterior (desta execução ou de execuções passadas,
// já que o inventário é lido do disco no início). Um MAC vazio
// (dispositivo sem entrada na tabela ARP) nunca é considerado
// conhecido, pra não colapsar vários aparelhos sem MAC num só registro.
func jaConhecido(mac string) bool {
	if mac == "" {
		return false
	}
	conhecidosMu.Lock()
	defer conhecidosMu.Unlock()
	_, existia := conhecidos[strings.ToUpper(mac)]
	return existia
}

// marcarVisto insere ou atualiza em memória o registro de um MAC visto
// agora, sem gravar em disco — a persistência fica a cargo de
// salvarConhecidos, chamada uma vez ao fim de cada varredura pra não
// reescrever o arquivo inteiro a cada dispositivo.
func marcarVisto(mac, ip string) {
	if mac == "" {
		return
	}
	chave := strings.ToUpper(mac)
	agora := time.Now()

	conhecidosMu.Lock()
	defer conhecidosMu.Unlock()
	if d, existia := conhecidos[chave]; existia {
		d.UltimoVisto = agora
		d.UltimoIP = ip
		conhecidos[chave] = d
	} else {
		conhecidos[chave] = dispositivoConhecido{MAC: chave, PrimeiroVisto: agora, UltimoVisto: agora, UltimoIP: ip}
	}
}
