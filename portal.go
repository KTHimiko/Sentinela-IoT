package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/http"
	"time"
)

// ---------- portal cativo ----------

// portalCativoHandler serve, pra quem foi redirecionado via DNAT (só
// acontece com dispositivos isolados tentando acessar HTTP), uma
// página explicando o motivo — em vez de simplesmente cortar o
// tráfego sem dizer nada. É o que um NAC comercial de verdade faz
// (portal cativo), e fecha o círculo do "linguagem simples pro usuário
// leigo" que é o diferencial do projeto: sem isso, o dono do
// dispositivo só veria a internet "quebrar" do nada.
func portalCativoHandler(w http.ResponseWriter, r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	isolamentosMu.Lock()
	estado, isolado := isolamentos[ip]
	isolamentosMu.Unlock()

	prazo := "Este dispositivo não consta mais como isolado — atualize a página em alguns segundos."
	if isolado {
		if estado.expiraEm.IsZero() {
			prazo = "Sem prazo definido — só volta ao normal se o administrador reconectar manualmente."
		} else if restante := time.Until(estado.expiraEm); restante > 0 {
			prazo = fmt.Sprintf("Reconecta automaticamente em aproximadamente %s.", restante.Round(time.Minute))
		} else {
			prazo = "O prazo já venceu — deve reconectar sozinho nos próximos segundos."
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dispositivo isolado — Sentinela IoT</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#fdecea; margin:0; padding:2rem; color:#333; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .caixa { background:white; border-radius:12px; padding:2rem; max-width:420px; box-shadow:0 2px 10px rgba(0,0,0,0.15); text-align:center; }
  h1 { font-size:1.3rem; margin-top:0; color:#7a0c00; }
  p { font-size:0.95rem; line-height:1.5; }
</style>
</head>
<body>
  <div class="caixa">
    <h1>🔒 Este dispositivo foi isolado da rede</h1>
    <p>Por segurança, o administrador da rede (Sentinela IoT) isolou este dispositivo (IP %s). Enquanto isolado, só esta página funciona — nenhum outro acesso à internet ou à rede local está disponível.</p>
    <p>%s</p>
    <p>Se você acha que isso é um engano, procure quem administra a rede.</p>
  </div>
</body>
</html>`, html.EscapeString(ip), html.EscapeString(prazo))
}

// gerarCertificadoAutoAssinado cria uma chave e um certificado válidos
// só pra essa execução, sem precisar de arquivo nenhum no disco nem de
// OpenSSL instalado — mantém o "zero configuração" do resto do
// projeto. Como é autoassinado, o navegador vai mostrar aviso de
// certificado inválido pra quem cair no portal via HTTPS; é uma
// limitação conhecida (todo portal cativo tem esse problema com
// HTTPS), mas quem clicar em "avançar mesmo assim" ainda vê a página
// explicando o isolamento, em vez de só um erro de conexão.
func gerarCertificadoAutoAssinado() (tls.Certificate, error) {
	chave, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	modelo := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Sentinela IoT - Portal Cativo"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &modelo, &modelo, &chave.PublicKey, chave)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: chave}, nil
}

// iniciarPortalCativo sobe dois servidores dedicados só pra essa
// página, em portas separadas do dashboard (8090): um HTTP (pra onde
// o DNAT da porta 80 redireciona) e um HTTPS (pra onde o DNAT da porta
// 443 redireciona). Os dois são necessários porque hoje a maioria dos
// sites/apps já tenta conectar direto em HTTPS — só redirecionar a
// porta 80 deixaria o navegador simplesmente falhar em silêncio na
// maior parte das tentativas de navegação.
func iniciarPortalCativo() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", portalCativoHandler)

	go func() {
		if err := http.ListenAndServe(":"+portaPortalCativo, mux); err != nil {
			fmt.Println("Portal cativo (HTTP) desativado (não consegui subir na porta", portaPortalCativo+"):", err)
		}
	}()

	go func() {
		cert, err := gerarCertificadoAutoAssinado()
		if err != nil {
			fmt.Println("Portal cativo (HTTPS) desativado (não consegui gerar certificado):", err)
			return
		}
		servidor := &http.Server{
			Addr:      ":" + portaPortalCativoTLS,
			Handler:   mux,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		}
		if err := servidor.ListenAndServeTLS("", ""); err != nil {
			fmt.Println("Portal cativo (HTTPS) desativado (não consegui subir na porta", portaPortalCativoTLS+"):", err)
		}
	}()
}
