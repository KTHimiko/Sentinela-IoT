package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// ---------- trusted device list ----------

// Devices marked as trusted (the owner's own laptop, a NAS that has always
// had SSH enabled and so on) stop producing "risk changed" events in the
// history. Without this a real NOC wears out whoever is watching, with
// repeated alerts about something already reviewed and knowingly accepted.
const trustedFile = "confiaveis.json"

var trustedMu sync.RWMutex
var trusted = make(map[string]bool) // key: uppercase MAC

func loadTrusted() {
	data, err := os.ReadFile(trustedFile)
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(data, &list) != nil {
		return
	}
	trustedMu.Lock()
	for _, mac := range list {
		trusted[strings.ToUpper(mac)] = true
	}
	trustedMu.Unlock()
}

func saveTrusted() {
	trustedMu.RLock()
	list := make([]string, 0, len(trusted))
	for mac := range trusted {
		list = append(list, mac)
	}
	trustedMu.RUnlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(trustedFile, data, 0644)
}

func isTrusted(mac string) bool {
	if mac == "" {
		return false
	}
	trustedMu.RLock()
	defer trustedMu.RUnlock()
	return trusted[strings.ToUpper(mac)]
}

func setTrusted(mac string, value bool) {
	mac = strings.ToUpper(mac)
	trustedMu.Lock()
	if value {
		trusted[mac] = true
	} else {
		delete(trusted, mac)
	}
	trustedMu.Unlock()
	saveTrusted()
}
