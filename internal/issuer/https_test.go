package issuer

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/adaptive-trust/atc/internal/transport"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestHTTPSIssuerPostsOnlyCSRAndParsesResult(t *testing.T) {
	issuer, err := newHTTPSIssuer("https://issuer.example.test/issue", &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: %#v", request)
		}
		body, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(body), "csr_pem") || strings.Contains(string(body), "private_key") {
			t.Fatalf("unexpected issuer payload: %s", body)
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"certificate_pem":"leaf","chain_pem":"fullchain","not_after":"2027-01-01T00:00:00Z"}`))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	result, err := issuer.Issue(context.Background(), CertificateRequest{CSRPEM: []byte("csr"), Lifetime: time.Hour})
	if err != nil || string(result.CertificatePEM) != "leaf" || string(result.ChainPEM) != "fullchain" {
		t.Fatalf("issue result = %#v, %v", result, err)
	}
}

func TestHTTPSIssuerRequiresHTTPS(t *testing.T) {
	if _, err := NewHTTPSIssuer("http://127.0.0.1:9000", transport.ClientTLSConfig{}); err == nil {
		t.Fatal("HTTP issuer URL accepted")
	}
}
