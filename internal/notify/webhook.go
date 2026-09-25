// Package notify delivers bounded, signed operational events.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Event struct {
	Type, Severity, AssetID, CertificateID, RenewalJobID, Message string
	OccurredAt                                                    time.Time
}

type Notifier interface {
	Notify(context.Context, Event) error
}

// Webhook signs JSON event bodies with HMAC-SHA256. The endpoint must be
// HTTPS; payloads deliberately carry only public identifiers and status text.
type Webhook struct {
	endpoint string
	secret   []byte
	client   *http.Client
}

func NewWebhook(endpoint, secret string) (*Webhook, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("alert webhook URL must be an absolute https URL")
	}
	if len(secret) < 32 {
		return nil, errors.New("alert webhook secret must be at least 32 characters")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return newWebhook(endpoint, []byte(secret), &http.Client{Timeout: 10 * time.Second, Transport: transport})
}

func newWebhook(endpoint string, secret []byte, client *http.Client) (*Webhook, error) {
	if client == nil || len(secret) == 0 {
		return nil, errors.New("webhook client and secret are required")
	}
	return &Webhook{endpoint: endpoint, secret: append([]byte(nil), secret...), client: client}, nil
}

func (webhook *Webhook) Notify(ctx context.Context, event Event) error {
	if event.Type == "" || event.Severity == "" || event.Message == "" {
		return errors.New("alert event type, severity, and message are required")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	payload, err := json.Marshal(struct {
		Type          string    `json:"type"`
		Severity      string    `json:"severity"`
		AssetID       string    `json:"asset_id,omitempty"`
		CertificateID string    `json:"certificate_id,omitempty"`
		RenewalJobID  string    `json:"renewal_job_id,omitempty"`
		Message       string    `json:"message"`
		OccurredAt    time.Time `json:"occurred_at"`
	}{event.Type, event.Severity, event.AssetID, event.CertificateID, event.RenewalJobID, event.Message, event.OccurredAt.UTC()})
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, webhook.secret)
	_, _ = mac.Write(payload)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook.endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("create alert webhook request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-ATC-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response, err := webhook.client.Do(request)
	if err != nil {
		return errors.New("alert webhook delivery failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("alert webhook returned %s", response.Status)
	}
	return nil
}
