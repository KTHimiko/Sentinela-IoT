package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func guardedStatus(method, host string, headers map[string]string) int {
	h := dashboardGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(method, "http://"+host+"/isolar", nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestGuardRefusesCrossSitePost(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"formulário do próprio painel", map[string]string{"Origin": "http://localhost:8090", "Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"curl, sem cabeçalhos de navegador", nil, http.StatusOK},
		{"formulário de outro site", map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"iframe isolado envia Origin null", map[string]string{"Origin": "null"}, http.StatusForbidden},
		{"só Sec-Fetch-Site acusando outro site", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"outra porta da mesma máquina", map[string]string{"Origin": "http://localhost:3000"}, http.StatusForbidden},
	}
	for _, c := range cases {
		if got := guardedStatus(http.MethodPost, "localhost:8090", c.headers); got != c.want {
			t.Errorf("%s: status %d, queria %d", c.name, got, c.want)
		}
	}
}

func TestGuardLetsCrossSiteGetThrough(t *testing.T) {
	// a GET changes nothing, and the browser will not let the other site
	// read the answer anyway
	if got := guardedStatus(http.MethodGet, "localhost:8090", map[string]string{"Sec-Fetch-Site": "cross-site"}); got != http.StatusOK {
		t.Errorf("GET de outro site: status %d", got)
	}
}

func TestGuardRefusesRebindingHost(t *testing.T) {
	// after DNS rebinding the attacker's page is same-origin, so only the
	// Host header gives it away
	same := map[string]string{"Origin": "http://rebind.evil.example:8090", "Sec-Fetch-Site": "same-origin"}
	if got := guardedStatus(http.MethodPost, "rebind.evil.example:8090", same); got != http.StatusForbidden {
		t.Errorf("host por nome: status %d, queria 403", got)
	}
	for _, host := range []string{"localhost:8090", "127.0.0.1:8090", "192.168.0.19:8090", "[::1]:8090"} {
		if got := guardedStatus(http.MethodGet, host, nil); got != http.StatusOK {
			t.Errorf("host %s: status %d, queria 200", host, got)
		}
	}
}

func TestForbiddenTarget(t *testing.T) {
	gwMAC, _ := net.ParseMAC("aa:bb:cc:00:00:01")
	ownMAC, _ := net.ParseMAC("aa:bb:cc:00:00:02")
	otherMAC, _ := net.ParseMAC("aa:bb:cc:00:00:03")
	n := &networkInfo{
		IP: net.ParseIP("192.168.0.19"), MAC: ownMAC,
		Gateway: net.ParseIP("192.168.0.1"), GatewayMAC: gwMAC,
	}
	cases := []struct {
		name   string
		ip     string
		mac    net.HardwareAddr
		refuse bool
	}{
		{"gateway", "192.168.0.1", gwMAC, true},
		{"roteador respondendo por outro IP", "192.168.0.2", gwMAC, true},
		{"esta máquina", "192.168.0.19", ownMAC, true},
		{"dispositivo comum", "192.168.0.50", otherMAC, false},
		{"MAC ainda desconhecido", "192.168.0.51", nil, false},
	}
	for _, c := range cases {
		err := forbiddenTarget(n, net.ParseIP(c.ip).To4(), c.mac)
		if (err != nil) != c.refuse {
			t.Errorf("%s: erro %v, queria recusa=%v", c.name, err, c.refuse)
		}
	}
}
