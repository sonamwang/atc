package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestWebhookSignsPublicEventPayload(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	webhook, err := newWebhook("https://alerts.example.test/atc", secret, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if request.Header.Get("X-ATC-Signature") != want || !strings.Contains(string(body), "certificate_id") {
			t.Fatalf("unexpected webhook request: header=%q body=%s", request.Header.Get("X-ATC-Signature"), body)
		}
		return &http.Response{StatusCode: http.StatusAccepted, Status: "202 Accepted", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if err := webhook.Notify(context.Background(), Event{Type: "certificate_risk", Severity: "HIGH", CertificateID: "cert_example", Message: "Certificate expires soon", OccurredAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookRejectsInsecureEndpointAndShortSecret(t *testing.T) {
	if _, err := NewWebhook("http://127.0.0.1/alerts", strings.Repeat("a", 32)); err == nil {
		t.Fatal("HTTP webhook accepted")
	}
	if _, err := NewWebhook("https://alerts.example.test", "short"); err == nil {
		t.Fatal("short secret accepted")
	}
}
