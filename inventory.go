package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- inventory of devices already seen ----------

// Without long-term memory every device that leaves and comes back (a
// phone in power saving, a rebooted appliance, or simply a scan that
// missed it for one cycle) shows up as if it were brand new — exactly the
// noise observed in the history, with the same device logged as new over
// and over. The inventory stores every MAC ever seen on disk, with when
// it first appeared and when it last answered, so monitoring can tell a
// genuinely unknown device from an old acquaintance that just came back.
// That memory survives restarts, as befits a NAC inventory.
const knownDevicesFile = "conhecidos.json"

type knownDevice struct {
	MAC       string    `json:"mac"`
	FirstSeen time.Time `json:"primeiro_visto"`
	LastSeen  time.Time `json:"ultimo_visto"`
	LastIP    string    `json:"ultimo_ip"`
}

var knownMu sync.Mutex
var knownDevices = make(map[string]knownDevice) // key: uppercase MAC

func loadKnownDevices() {
	data, err := os.ReadFile(knownDevicesFile)
	if err != nil {
		return
	}
	var list []knownDevice
	if json.Unmarshal(data, &list) != nil {
		return
	}
	knownMu.Lock()
	for _, d := range list {
		knownDevices[strings.ToUpper(d.MAC)] = d
	}
	knownMu.Unlock()
}

func saveKnownDevices() {
	knownMu.Lock()
	list := make([]knownDevice, 0, len(knownDevices))
	for _, d := range knownDevices {
		list = append(list, d)
	}
	knownMu.Unlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(knownDevicesFile, data, 0644)
}

// alreadyKnown reports, without changing anything, whether a MAC was seen
// in an earlier scan (in this run or in a past one, since the inventory is
// read from disk at startup). An empty MAC (a device with no ARP entry) is
// never considered known, so several device-less hosts do not collapse
// into a single record.
func alreadyKnown(mac string) bool {
	if mac == "" {
		return false
	}
	knownMu.Lock()
	defer knownMu.Unlock()
	_, existed := knownDevices[strings.ToUpper(mac)]
	return existed
}

// markSeen inserts or refreshes the in-memory record for a MAC seen right
// now, without writing to disk — persistence is left to saveKnownDevices,
// called once at the end of each scan so the whole file is not rewritten
// for every single device.
func markSeen(mac, ip string) {
	if mac == "" {
		return
	}
	key := strings.ToUpper(mac)
	now := time.Now()

	knownMu.Lock()
	defer knownMu.Unlock()
	if d, existed := knownDevices[key]; existed {
		d.LastSeen = now
		d.LastIP = ip
		knownDevices[key] = d
	} else {
		knownDevices[key] = knownDevice{MAC: key, FirstSeen: now, LastSeen: now, LastIP: ip}
	}
}
