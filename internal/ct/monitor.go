// Package ct queries a configured Certificate Transparency search service.
// It is an opt-in visibility feature: the control plane never contacts a CT
// service unless an administrator supplies an HTTPS URL template.
package ct

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 2 << 20

type Entry struct {
	ID           int64     `json:"id"`
	Issuer       string    `json:"issuer"`
	CommonName   string    `json:"common_name"`
	DNSNames     []string  `json:"dns_names"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	LoggedAt     time.Time `json:"logged_at"`
}

type Monitor struct {
	template *url.URL
	client   *http.Client
}

// NewMonitor accepts an HTTPS URL template whose query contains exactly one
// {domain} placeholder, for example:
// https://crt.sh/?q={domain}&output=json
func NewMonitor(endpoint string) (*Monitor, error) {
	parsed, err := parseTemplate(endpoint)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &Monitor{template: parsed, client: &http.Client{Timeout: 20 * time.Second, Transport: transport}}, nil
}

func newMonitor(endpoint string, client *http.Client) (*Monitor, error) {
	parsed, err := parseTemplate(endpoint)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("CT HTTP client is required")
	}
	return &Monitor{template: parsed, client: client}, nil
}

func parseTemplate(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("CT monitor URL must be an absolute HTTPS URL without credentials or fragment")
	}
	if strings.Count(parsed.RawQuery, "{domain}") != 1 {
		return nil, errors.New("CT monitor URL query must contain exactly one {domain} placeholder")
	}
	return parsed, nil
}

func (m *Monitor) Lookup(ctx context.Context, domain string) ([]Entry, error) {
	if m == nil || m.client == nil || m.template == nil {
		return nil, errors.New("CT monitor is not configured")
	}
	if !validDomain(domain) {
		return nil, errors.New("invalid CT lookup domain")
	}
	endpoint := *m.template
	endpoint.RawQuery = strings.Replace(endpoint.RawQuery, "{domain}", url.QueryEscape(domain), 1)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := m.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query CT monitor: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CT monitor returned %s", response.Status)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes))
	var rows []crtSHRow
	if err := decoder.Decode(&rows); err != nil {
		return nil, errors.New("CT monitor returned invalid JSON")
	}
	if len(rows) > 10000 {
		return nil, errors.New("CT monitor response has too many entries")
	}
	entries := make([]Entry, 0, len(rows))
	for _, row := range rows {
		entry, err := row.entry()
		if err != nil {
			return nil, fmt.Errorf("decode CT monitor entry: %w", err)
		}
		if entry.ID != 0 {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

type crtSHRow struct {
	ID           int64  `json:"id"`
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	EntryTime    string `json:"entry_timestamp"`
}

func (r crtSHRow) entry() (Entry, error) {
	parse := func(value string) (time.Time, error) {
		if value == "" {
			return time.Time{}, nil
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05.999999-07", "2006-01-02 15:04:05"} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
	}
	notBefore, err := parse(r.NotBefore)
	if err != nil {
		return Entry{}, err
	}
	notAfter, err := parse(r.NotAfter)
	if err != nil {
		return Entry{}, err
	}
	loggedAt, err := parse(r.EntryTime)
	if err != nil {
		return Entry{}, err
	}
	names := strings.FieldsFunc(r.NameValue, func(r rune) bool { return r == '\n' || r == '\r' })
	if len(names) > 1000 {
		return Entry{}, errors.New("too many DNS names")
	}
	return Entry{ID: r.ID, Issuer: r.IssuerName, CommonName: r.CommonName, DNSNames: names, SerialNumber: r.SerialNumber, NotBefore: notBefore, NotAfter: notAfter, LoggedAt: loggedAt}, nil
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || strings.HasPrefix(domain, "*.") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}
