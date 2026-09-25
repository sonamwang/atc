package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/adaptive-trust/atc/internal/issuer"
	"github.com/adaptive-trust/atc/internal/renewal"
	"github.com/adaptive-trust/atc/internal/storage"
)

type RenewalClient struct {
	ServerURL, Token, JobID string
	Current                 renewal.State
	HTTPClient              *http.Client
}

func (c *RenewalClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}
func (c *RenewalClient) endpoint(path string) string {
	return strings.TrimRight(c.ServerURL, "/") + path
}
func (c *RenewalClient) Issue(ctx context.Context, request issuer.CertificateRequest) (issuer.CertificateResult, error) {
	body, err := json.Marshal(map[string]any{"csr_pem": string(request.CSRPEM), "lifetime_seconds": int64(request.Lifetime / time.Second)})
	if err != nil {
		return issuer.CertificateResult{}, err
	}
	response, err := c.request(ctx, http.MethodPost, "/api/v1/agent/renewals/"+c.JobID+"/csr", body)
	if err != nil {
		return issuer.CertificateResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return issuer.CertificateResult{}, fmt.Errorf("certificate issuer returned %s", response.Status)
	}
	var result struct {
		CertificatePEM string    `json:"certificate_pem"`
		ChainPEM       string    `json:"chain_pem"`
		NotAfter       time.Time `json:"not_after"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return issuer.CertificateResult{}, err
	}
	return issuer.CertificateResult{CertificatePEM: []byte(result.CertificatePEM), ChainPEM: []byte(result.ChainPEM), NotAfter: result.NotAfter}, nil
}
func (c *RenewalClient) Record(ctx context.Context, next renewal.State) error {
	current := c.Current
	if current == "" {
		current = renewal.RenewalPending
	}
	body, err := json.Marshal(map[string]string{"from": string(current), "to": string(next)})
	if err != nil {
		return err
	}
	response, err := c.request(ctx, http.MethodPost, "/api/v1/agent/renewals/"+c.JobID+"/state", body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("renewal state update returned %s", response.Status)
	}
	c.Current = next
	return nil
}
func (c *RenewalClient) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	return c.client().Do(request)
}
func FetchRenewals(ctx context.Context, serverURL, token string, client *http.Client) ([]storage.RenewalCommand, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(serverURL, "/")+"/api/v1/agent/renewals", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renewal poll returned %s", response.Status)
	}
	var commands []storage.RenewalCommand
	if err := json.NewDecoder(response.Body).Decode(&commands); err != nil {
		return nil, err
	}
	return commands, nil
}
