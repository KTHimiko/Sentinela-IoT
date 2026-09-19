package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ---------- distributed mode: agent and central ----------

// ARP is a link-layer protocol and does not cross a router, so a single
// instance can only contain what lives in its own subnet. The way out is
// the one real NAC products take: put an enforcement point inside each
// subnet and aggregate them. An agent scans and contains its own subnet
// and exposes the result over JSON; a central scans its own subnet too and
// additionally pulls every agent's view into one dashboard, forwarding any
// isolation order to whichever agent owns that device.
//
// Modes come from MODO:
//   - unset      standalone, exactly the original behaviour, no API
//   - "agente"   standalone plus the JSON API (requires a token)
//   - "central"  standalone plus aggregation of the agents in AGENTES
const (
	modeStandalone = ""
	modeAgent      = "agente"
	modeCentral    = "central"
)

// apiPort is where the agent's JSON API listens, deliberately separate
// from the dashboard's port. In agent mode the dashboard is bound to
// localhost and only this port is reachable from the network: exposing the
// dashboard itself would leave its "isolate" button open to anyone on the
// agent's LAN, with no authentication at all.
const defaultAPIPort = "8095"

// agentSnapshot is what an agent answers on /api/dispositivos.
type agentSnapshot struct {
	Agent   string         `json:"agent"`
	Network string         `json:"network"`
	Updated time.Time      `json:"updated"`
	Devices []deviceResult `json:"devices"`
}

// remoteAgent is an entry of AGENTES: an optional label plus the base URL.
type remoteAgent struct {
	Name string
	URL  string
}

// parseAgents reads AGENTES, a comma-separated list where each entry is
// either a bare URL or "name=url", e.g.
// "andar1=http://192.168.3.10:8095,http://192.168.1.10:8095".
func parseAgents(value string) []remoteAgent {
	var agents []remoteAgent
	for _, piece := range strings.Split(value, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		name, raw := "", piece
		if label, rest, found := strings.Cut(piece, "="); found {
			name, raw = strings.TrimSpace(label), strings.TrimSpace(rest)
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			fmt.Printf("AGENTES: ignorando %q (não é uma URL válida, use algo como http://192.168.3.10:8095)\n", piece)
			continue
		}
		if name == "" {
			name = parsed.Host
		}
		agents = append(agents, remoteAgent{Name: name, URL: strings.TrimRight(parsed.String(), "/")})
	}
	return agents
}

// ---------- authentication ----------

var apiToken string

// tokenRequired wraps a handler so it only runs for callers presenting the
// shared token. Without this an HTTP endpoint that isolates devices, open
// on the network, would be a denial-of-service vector: anyone on the LAN
// could cut off whoever they liked. subtle.ConstantTimeCompare avoids
// leaking the token's length or prefix through response timing.
func tokenRequired(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sent := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(sent), []byte(apiToken)) != 1 {
			http.Error(w, "token inválido", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ---------- agent side ----------

// registerAgentAPI publishes the JSON API on its own mux, returned to the
// caller so it can be served on a separate port from the dashboard.
func registerAgentAPI(network *networkInfo, agentName string) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/dispositivos", tokenRequired(func(w http.ResponseWriter, r *http.Request) {
		results, updated := readCache()
		local := make([]deviceResult, 0, len(results))
		for _, d := range results {
			if d.Agent == "" { // never relay what came from another agent
				local = append(local, d)
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(agentSnapshot{
			Agent:   agentName,
			Network: network.IPNet.String(),
			Updated: updated,
			Devices: local,
		})
	}))

	mux.HandleFunc("/api/isolar", tokenRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP      string `json:"ip"`
			Minutes int    `json:"minutos"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "corpo inválido", http.StatusBadRequest)
			return
		}
		if err := isolateByIP(network, req.IP, time.Duration(req.Minutes)*time.Minute); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		refreshCache(network)
		w.WriteHeader(http.StatusNoContent)
	}))

	mux.HandleFunc("/api/reconectar", tokenRequired(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "método não permitido", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "corpo inválido", http.StatusBadRequest)
			return
		}
		if err := reconnectDevice(req.IP, network); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		refreshCache(network)
		w.WriteHeader(http.StatusNoContent)
	}))

	return mux
}

// ---------- central side ----------

var agentsMu sync.RWMutex
var remoteResults []deviceResult
var agentErrors = map[string]string{}

var apiClient = &http.Client{Timeout: 4 * time.Second}

// fetchAgent asks one agent for its current view. It never blocks the
// dashboard for long: a dead agent fails on the client timeout and is
// reported as an error next to its name, instead of stalling the page.
func fetchAgent(agent remoteAgent) ([]deviceResult, error) {
	req, err := http.NewRequest(http.MethodGet, agent.URL+"/api/dispositivos", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)

	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("respondeu %s", resp.Status)
	}

	var snapshot agentSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&snapshot); err != nil {
		return nil, err
	}
	for i := range snapshot.Devices {
		// stamp the origin so the dashboard knows where to send actions,
		// and so this never gets relayed onwards as if it were local
		snapshot.Devices[i].Agent = agent.Name
		snapshot.Devices[i].AgentURL = agent.URL
		// it is in another subnet, but it IS containable — by its own
		// agent — so it must not carry the "cannot be contained" flag
		snapshot.Devices[i].OutsideSubnet = false
	}
	return snapshot.Devices, nil
}

// refreshAgents queries every agent in parallel and stores the merged
// result, along with whatever errors happened, for the dashboard to show.
func refreshAgents(agents []remoteAgent) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	merged := []deviceResult{}
	failures := map[string]string{}

	for _, agent := range agents {
		wg.Add(1)
		go func(agent remoteAgent) {
			defer wg.Done()
			devices, err := fetchAgent(agent)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures[agent.Name] = err.Error()
				return
			}
			merged = append(merged, devices...)
		}(agent)
	}
	wg.Wait()

	agentsMu.Lock()
	remoteResults = merged
	agentErrors = failures
	agentsMu.Unlock()
}

func readAgentCache() ([]deviceResult, map[string]string) {
	agentsMu.RLock()
	defer agentsMu.RUnlock()
	return remoteResults, agentErrors
}

// startAgentPolling keeps the central's view of the agents current, on the
// same rhythm as the local scan.
func startAgentPolling(agents []remoteAgent, interval time.Duration) {
	go func() {
		for {
			refreshAgents(agents)
			time.Sleep(interval)
		}
	}()
}

// proxyAction forwards an isolate or reconnect order to the agent that
// owns the device. The central itself cannot contain anything outside its
// own subnet, so this is the whole point of the distributed mode.
func proxyAction(agentURL, path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, agentURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := apiClient.Do(req)
	if err != nil {
		return fmt.Errorf("não consegui falar com o agente: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("o agente recusou: %s", strings.TrimSpace(string(detail)))
	}
	return nil
}

// agentURLFor finds which agent reported a given IP, so an action can be
// routed to it. An empty result means the device is local.
func agentURLFor(ip string) string {
	devices, _ := readAgentCache()
	for _, d := range devices {
		if d.IP == ip {
			return d.AgentURL
		}
	}
	return ""
}

// ---------- startup ----------

// configureDistributedMode reads MODO, GUARITA_TOKEN and AGENTES, and
// reports the mode plus the agents to poll. It fails closed: in agent or
// central mode without a token, the distributed part simply does not start
// and the program carries on standalone, rather than publishing an
// unauthenticated isolation endpoint on the network.
func configureDistributedMode() (mode string, agents []remoteAgent) {
	mode = strings.ToLower(strings.TrimSpace(os.Getenv("MODO")))
	if mode != modeAgent && mode != modeCentral {
		return modeStandalone, nil
	}

	apiToken = os.Getenv("GUARITA_TOKEN")
	if apiToken == "" {
		fmt.Printf("MODO=%s ignorado: defina GUARITA_TOKEN com um segredo compartilhado entre a central e os agentes.\n", mode)
		fmt.Println("   Sem isso, qualquer um na rede poderia isolar qualquer dispositivo. Seguindo em modo autônomo.")
		return modeStandalone, nil
	}

	if mode == modeCentral {
		agents = parseAgents(os.Getenv("AGENTES"))
		if len(agents) == 0 {
			fmt.Println("MODO=central sem nenhum agente válido em AGENTES — a central vai mostrar só a própria sub-rede.")
		}
	}
	return mode, agents
}
