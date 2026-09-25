package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/adaptive-trust/atc/internal/transport"
)

func main() {
	flags := flag.NewFlagSet("atc", flag.ExitOnError)
	server := flags.String("server", env("ATC_SERVER_URL", "http://127.0.0.1:8080"), "ATC server URL")
	token := flags.String("token", os.Getenv("ATC_OPERATOR_TOKEN"), "operator bootstrap token")
	tlsCAFile := flags.String("tls-ca-file", os.Getenv("ATC_TLS_CA_FILE"), "PEM trust bundle for an HTTPS control plane")
	tlsCertificateFile := flags.String("tls-cert-file", os.Getenv("ATC_CLIENT_TLS_CERT_FILE"), "PEM client certificate for mutual TLS")
	tlsKeyFile := flags.String("tls-key-file", os.Getenv("ATC_CLIENT_TLS_KEY_FILE"), "PEM client private key for mutual TLS")
	flags.Parse(os.Args[1:])
	if err := transport.ValidateControlPlaneURL(*server); err != nil {
		die("invalid -server: " + err.Error())
	}
	client, err := transport.NewHTTPClient(*server, 15*time.Second, transport.ClientTLSConfig{CAFile: *tlsCAFile, CertificateFile: *tlsCertificateFile, KeyFile: *tlsKeyFile})
	if err != nil {
		die("configure control-plane TLS: " + err.Error())
	}
	args := flags.Args()
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("atc 0.1.0")
		return
	}
	if len(args) == 1 && args[0] == "health" {
		run(client, *server, "GET", "/api/v1/health", "", nil)
		return
	}
	if len(args) == 2 && args[0] == "agent" && args[1] == "status" {
		run(client, *server, "GET", "/api/v1/agents", *token, nil)
		return
	}
	if len(args) == 3 && args[0] == "agent" && args[1] == "revoke" {
		if *token == "" {
			die("--token or ATC_OPERATOR_TOKEN is required")
		}
		run(client, *server, "POST", "/api/v1/agents/"+args[2]+"/revoke", *token, nil)
		return
	}
	if len(args) == 2 && args[0] == "certificates" && args[1] == "list" {
		run(client, *server, "GET", "/api/v1/certificates", *token, nil)
		return
	}
	if len(args) == 3 && args[0] == "certificates" && args[1] == "inspect" {
		run(client, *server, "GET", "/api/v1/certificates/"+args[2], *token, nil)
		return
	}
	if len(args) == 2 && args[0] == "renewals" && args[1] == "list" {
		run(client, *server, "GET", "/api/v1/renewals", *token, nil)
		return
	}
	if len(args) == 2 && args[0] == "findings" && args[1] == "list" {
		run(client, *server, "GET", "/api/v1/findings", *token, nil)
		return
	}
	if len(args) == 3 && args[0] == "certificates" && (args[1] == "renew" || args[1] == "rotate") {
		if *token == "" {
			die("--token or ATC_OPERATOR_TOKEN is required")
		}
		path := "/api/v1/certificates/" + args[2] + "/renew"
		if args[1] == "rotate" {
			path = "/api/v1/certificates/" + args[2] + "/rotate"
		}
		run(client, *server, "POST", path, *token, nil)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: atc [-server URL] [-token TOKEN] <version|health|agent status|agent revoke ID|certificates list|certificates inspect ID|certificates renew ID|certificates rotate ID|renewals list|findings list>")
	os.Exit(2)
}
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func die(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(2) }
func run(client *http.Client, server, method, path, token string, payload any) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			die(err.Error())
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, strings.TrimRight(server, "/")+path, body)
	if err != nil {
		die(err.Error())
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if method == "POST" {
		request.Header.Set("Content-Type", "application/json")
		if strings.HasSuffix(path, "/revoke") {
			request.Header.Set("X-ATC-Confirm", "revoke")
		} else {
			request.Header.Set("X-ATC-Confirm", "renewal")
		}
		request.Header.Set("Idempotency-Key", idempotencyKey())
	}
	response, err := client.Do(request)
	if err != nil {
		die(err.Error())
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		die(err.Error())
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		die(fmt.Sprintf("server returned %s: %s", response.Status, strings.TrimSpace(string(data))))
	}
	var formatted bytes.Buffer
	if json.Indent(&formatted, data, "", "  ") == nil {
		fmt.Println(formatted.String())
		return
	}
	fmt.Println(string(data))
}
func idempotencyKey() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		die("generate idempotency key: " + err.Error())
	}
	return "cli-" + hex.EncodeToString(bytes)
}
