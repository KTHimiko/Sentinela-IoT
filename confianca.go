package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// ---------- lista de dispositivos confiáveis ----------

// Dispositivos marcados como confiáveis (o próprio notebook do dono,
// uma NAS que sempre teve SSH ligado etc.) param de gerar eventos de
// "mudança de risco" no histórico — sem isso, um NOC de verdade cansa
// quem está olhando com alertas repetidos pra coisa que já foi revisada
// e aceita conscientemente.
const arquivoConfiaveis = "confiaveis.json"

var confiaveisMu sync.RWMutex
var confiaveis = make(map[string]bool) // chave: MAC em maiúsculas

func carregarConfiaveis() {
	dados, err := os.ReadFile(arquivoConfiaveis)
	if err != nil {
		return
	}
	var lista []string
	if json.Unmarshal(dados, &lista) != nil {
		return
	}
	confiaveisMu.Lock()
	for _, mac := range lista {
		confiaveis[strings.ToUpper(mac)] = true
	}
	confiaveisMu.Unlock()
}

func salvarConfiaveis() {
	confiaveisMu.RLock()
	lista := make([]string, 0, len(confiaveis))
	for mac := range confiaveis {
		lista = append(lista, mac)
	}
	confiaveisMu.RUnlock()

	dados, err := json.MarshalIndent(lista, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(arquivoConfiaveis, dados, 0644)
}

func ehConfiavel(mac string) bool {
	if mac == "" {
		return false
	}
	confiaveisMu.RLock()
	defer confiaveisMu.RUnlock()
	return confiaveis[strings.ToUpper(mac)]
}

func marcarConfiavel(mac string, confiavel bool) {
	mac = strings.ToUpper(mac)
	confiaveisMu.Lock()
	if confiavel {
		confiaveis[mac] = true
	} else {
		delete(confiaveis, mac)
	}
	confiaveisMu.Unlock()
	salvarConfiaveis()
}
