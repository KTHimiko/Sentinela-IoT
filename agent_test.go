package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testNetwork(t *testing.T) *networkInfo {
	t.Helper()
	_, ipNet, err := net.ParseCIDR("192.168.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return &networkInfo{
		Interface: "test0",
		IP:        net.ParseIP("192.168.2.156").To4(),
		IPNet:     ipNet,
		Gateway:   net.ParseIP("192.168.2.1").To4(),
	}
}

func TestParseAgents(t *testing.T) {
	agents := parseAgents("andar1=http://192.168.3.10:8095, http://192.168.1.10:8095 ,,sem-esquema")
	if len(agents) != 2 {
		t.Fatalf("esperava 2 agentes válidos, obtive %d: %+v", len(agents), agents)
	}
	if agents[0].Name != "andar1" || agents[0].URL != "http://192.168.3.10:8095" {
		t.Errorf("entrada com rótulo mal interpretada: %+v", agents[0])
	}
	// without a label, the host itself becomes the name
	if agents[1].Name != "192.168.1.10:8095" {
		t.Errorf("entrada sem rótulo deveria usar o host como nome, obtive %q", agents[1].Name)
	}
}

func TestAPIRequiresToken(t *testing.T) {
	apiToken = "segredo"
	mux := registerAgentAPI(testNetwork(t), "agente-teste")

	for _, header := range []string{"", "Bearer errado", "segredo-quase"} {
		req := httptest.NewRequest(http.MethodGet, "/api/dispositivos", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q deveria ser recusado, obtive %d", header, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/dispositivos", nil)
	req.Header.Set("Authorization", "Bearer segredo")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token correto deveria passar, obtive %d", rec.Code)
	}
}

func TestAPINeverRelaysRemoteDevices(t *testing.T) {
	apiToken = "segredo"
	stateMu.Lock()
	lastResults = []deviceResult{
		{IP: "192.168.2.10", Risk: "baixo"},
		{IP: "192.168.3.20", Risk: "alto", Agent: "outro", AgentURL: "http://x"},
	}
	lastUpdate = time.Now()
	stateMu.Unlock()

	mux := registerAgentAPI(testNetwork(t), "agente-teste")
	req := httptest.NewRequest(http.MethodGet, "/api/dispositivos", nil)
	req.Header.Set("Authorization", "Bearer segredo")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	var snapshot agentSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Devices) != 1 || snapshot.Devices[0].IP != "192.168.2.10" {
		t.Errorf("o agente deveria devolver só os dispositivos locais, obtive %+v", snapshot.Devices)
	}
	if snapshot.Agent != "agente-teste" || snapshot.Network != "192.168.2.0/24" {
		t.Errorf("identificação do agente errada: %+v", snapshot)
	}
}

func TestFetchAgentStampsOrigin(t *testing.T) {
	apiToken = "segredo"
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(agentSnapshot{
			Agent:   "remoto",
			Network: "192.168.3.0/24",
			Devices: []deviceResult{{IP: "192.168.3.20", OutsideSubnet: true}},
		})
	}))
	defer server.Close()

	devices, err := fetchAgent(remoteAgent{Name: "andar1", URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer segredo" {
		t.Errorf("o token deveria ir no cabeçalho, obtive %q", gotAuth)
	}
	if len(devices) != 1 {
		t.Fatalf("esperava 1 dispositivo, obtive %d", len(devices))
	}
	d := devices[0]
	if d.Agent != "andar1" || d.AgentURL != server.URL {
		t.Errorf("origem não foi carimbada: %+v", d)
	}
	// it is in another subnet, but its agent can contain it, so the flag
	// that hides the isolate button must be cleared
	if d.OutsideSubnet {
		t.Error("dispositivo vindo de um agente não deveria ficar marcado como inalcançável")
	}
}

func TestFetchAgentReportsFailure(t *testing.T) {
	apiToken = "segredo"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "token inválido", http.StatusUnauthorized)
	}))
	defer server.Close()

	if _, err := fetchAgent(remoteAgent{Name: "andar1", URL: server.URL}); err == nil {
		t.Error("um agente que recusa o token deveria virar erro, não silêncio")
	}
}

func TestProxyActionForwardsOrder(t *testing.T) {
	apiToken = "segredo"
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/isolar" {
			t.Errorf("caminho errado: %s", r.URL.Path)
		}
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := proxyAction(server.URL, "/api/isolar", map[string]any{"ip": "192.168.3.20", "minutos": 60})
	if err != nil {
		t.Fatal(err)
	}
	if body["ip"] != "192.168.3.20" {
		t.Errorf("IP não chegou ao agente: %+v", body)
	}
}

func TestProxyActionSurfacesRefusal(t *testing.T) {
	apiToken = "segredo"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "192.168.3.20 já está isolado", http.StatusConflict)
	}))
	defer server.Close()

	err := proxyAction(server.URL, "/api/isolar", map[string]any{"ip": "192.168.3.20"})
	if err == nil || !strings.Contains(err.Error(), "já está isolado") {
		t.Errorf("a recusa do agente deveria chegar ao usuário, obtive %v", err)
	}
}

// The distributed mode must fail closed: asking for agent or central mode
// without a shared token has to fall back to standalone, never publish an
// unauthenticated isolation endpoint on the network.
func TestDistributedModeFailsClosedWithoutToken(t *testing.T) {
	t.Setenv("IMMUNEGATE_TOKEN", "")

	for _, requested := range []string{"agente", "central", "AGENTE"} {
		t.Setenv("MODO", requested)
		apiToken = "resíduo de outro teste"
		mode, agents := configureDistributedMode()
		if mode != modeStandalone {
			t.Errorf("MODO=%s sem token deveria cair pra autônomo, obtive %q", requested, mode)
		}
		if len(agents) != 0 {
			t.Errorf("MODO=%s sem token não deveria agregar agente nenhum", requested)
		}
	}

	t.Setenv("MODO", "central")
	t.Setenv("IMMUNEGATE_TOKEN", "segredo")
	t.Setenv("AGENTES", "andar1=http://192.168.3.10:8095")
	mode, agents := configureDistributedMode()
	if mode != modeCentral || len(agents) != 1 {
		t.Errorf("com token, a central deveria subir com 1 agente; obtive %q e %d", mode, len(agents))
	}
	if apiToken != "segredo" {
		t.Errorf("o token deveria ter sido carregado, obtive %q", apiToken)
	}
}

func TestAgentURLForRoutesToOwner(t *testing.T) {
	agentsMu.Lock()
	remoteResults = []deviceResult{{IP: "192.168.3.20", Agent: "andar1", AgentURL: "http://192.168.3.10:8095"}}
	agentsMu.Unlock()

	if got := agentURLFor("192.168.3.20"); got != "http://192.168.3.10:8095" {
		t.Errorf("dispositivo remoto deveria rotear pro agente dono, obtive %q", got)
	}
	if got := agentURLFor("192.168.2.10"); got != "" {
		t.Errorf("dispositivo local não deveria rotear pra agente nenhum, obtive %q", got)
	}

	agentsMu.Lock()
	remoteResults = nil
	agentsMu.Unlock()
}
