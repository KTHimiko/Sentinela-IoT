package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// The dashboard has no login: it was written for someone sitting at the
// machine. These checks are what keeps that assumption true, since its
// "isolate" button cuts a device off the network.

// dashboardGuard rejects two kinds of request a browser can be tricked into
// sending on the user's behalf.
//
// Cross-site POSTs: any page the user visits can submit a plain HTML form
// to http://localhost:8090/isolar — a form POST is a "simple request" and
// needs no CORS preflight, so the browser sends it with no questions asked.
// Browsers attach Origin to cross-origin POSTs, and Sec-Fetch-Site to all
// of them in current versions, so a request that declares another origin
// is refused. A request with neither header did not come from a browser
// page (curl, a script on the machine) and is let through.
//
// DNS rebinding: an attacker's domain that re-resolves to 127.0.0.1 makes
// the attacker's page same-origin with the dashboard, and the Origin check
// passes. What gives it away is the Host header, which carries the
// attacker's domain name. The dashboard is only ever reached by IP or as
// "localhost", so any other name is refused.
func dashboardGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host) {
			http.Error(w, "host não permitido", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && crossSite(r) {
			http.Error(w, "requisição de outra origem recusada", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func allowedHost(hostport string) bool {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport // no port in the header
	}
	return host == "localhost" || net.ParseIP(host) != nil
}

func crossSite(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		// "null" is what sandboxed iframes and file:// pages send
		return err != nil || u.Host != r.Host
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return false
	}
	return true
}

// forbiddenTarget refuses to contain the gateway or this machine itself.
// Poisoning the gateway's view of the network takes everyone offline, and
// containing our own address blocks the program's own traffic. Checked
// against the MAC as well as the IP: a router answering on a second
// address is still the router.
func forbiddenTarget(network *networkInfo, ip net.IP, mac net.HardwareAddr) error {
	switch {
	case ip.Equal(network.Gateway), sameMAC(mac, network.GatewayMAC):
		return fmt.Errorf("%s é o gateway da rede: isolá-lo derrubaria a conexão de todos", ip)
	case ip.Equal(network.IP), sameMAC(mac, network.MAC):
		return fmt.Errorf("%s é esta própria máquina", ip)
	}
	return nil
}

func sameMAC(a, b net.HardwareAddr) bool {
	return len(a) > 0 && bytes.Equal(a, b)
}
