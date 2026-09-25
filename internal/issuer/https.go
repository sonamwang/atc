package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adaptive-trust/atc/internal/transport"
)

// HTTPSIssuer adapts an enterprise CA HTTPS endpoint to CertificateIssuer.
// The endpoint accepts a JSON object with csr_pem and lifetime_seconds, then
// returns certificate_pem, chain_pem, and not_after. It is deliberately not an
// ACME implementation; challenge orchestration belongs to a dedicated issuer.
type HTTPSIssuer struct {
	endpoint string
	client   *http.Client
}

func NewHTTPSIssuer(endpoint string, tlsConfig transport.ClientTLSConfig) (*HTTPSIssuer, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("HTTPS issuer URL must be an absolute https URL")
	}
	if err := transport.ValidateControlPlaneURL(endpoint); err != nil {
		return nil, fmt.Errorf("validate HTTPS issuer URL: %w", err)
	}
	client, err := transport.NewHTTPClient(endpoint, 30*time.Second, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("configure HTTPS issuer client: %w", err)
	}
	return newHTTPSIssuer(endpoint, client)
}

func newHTTPSIssuer(endpoint string, client *http.Client) (*HTTPSIssuer, error) {
	if client == nil {
		return nil, errors.New("HTTPS issuer client is required")
	}
	return &HTTPSIssuer{endpoint: endpoint, client: client}, nil
}

func (issuer *HTTPSIssuer) Issue(ctx context.Context, request CertificateRequest) (CertificateResult, error) {
	if len(request.CSRPEM) == 0 || len(request.CSRPEM) > 128<<10 {
		return CertificateResult{}, errors.New("CSR must be between 1 byte and 128 KiB")
	}
	payload, err := json.Marshal(map[string]any{"csr_pem": string(request.CSRPEM), "lifetime_seconds": int64(request.Lifetime / time.Second)})
	if err != nil {
		return CertificateResult{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer.endpoint, bytes.NewReader(payload))
	if err != nil {
		return CertificateResult{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := issuer.client.Do(httpRequest)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("request HTTPS issuer: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return CertificateResult{}, fmt.Errorf("HTTPS issuer returned %s", response.Status)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 512<<10))
	decoder.DisallowUnknownFields()
	var result struct {
		CertificatePEM string    `json:"certificate_pem"`
		ChainPEM       string    `json:"chain_pem"`
		NotAfter       time.Time `json:"not_after"`
	}
	if err := decoder.Decode(&result); err != nil {
		return CertificateResult{}, errors.New("HTTPS issuer returned invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return CertificateResult{}, errors.New("HTTPS issuer returned invalid JSON")
	}
	if result.CertificatePEM == "" || len(result.CertificatePEM) > 256<<10 || len(result.ChainPEM) > 256<<10 || result.NotAfter.IsZero() {
		return CertificateResult{}, errors.New("HTTPS issuer returned incomplete certificate material")
	}
	return CertificateResult{CertificatePEM: []byte(result.CertificatePEM), ChainPEM: []byte(result.ChainPEM), NotAfter: result.NotAfter}, nil
}

func (issuer *HTTPSIssuer) String() string { return strings.TrimSpace(issuer.endpoint) }
