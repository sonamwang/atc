package ct

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestMonitorRequiresHTTPSDomainTemplate(t *testing.T) {
	if _, err := NewMonitor("http://ct.example.test/?q={domain}"); err == nil {
		t.Fatal("HTTP monitor accepted")
	}
	if _, err := NewMonitor("https://ct.example.test/?q=static"); err == nil {
		t.Fatal("template without domain placeholder accepted")
	}
}

func TestLookupEscapesDomainAndDecodesEntries(t *testing.T) {
	client := &http.Client{Transport: roundTripper(func(request *http.Request) (*http.Response, error) {
		if request.URL.Query().Get("q") != "api.example.test" {
			t.Fatalf("query = %q", request.URL.RawQuery)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`[{"id":22,"issuer_name":"Example CA","common_name":"api.example.test","name_value":"api.example.test\nwww.example.test","serial_number":"01","not_before":"2026-01-01 00:00:00","not_after":"2026-04-01 00:00:00","entry_timestamp":"2026-01-01T00:01:00Z"}]`))}, nil
	})}
	monitor, err := newMonitor("https://ct.example.test/?q={domain}&output=json", client)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := monitor.Lookup(context.Background(), "api.example.test")
	if err != nil || len(entries) != 1 || entries[0].ID != 22 || len(entries[0].DNSNames) != 2 {
		t.Fatalf("entries=%#v err=%v", entries, err)
	}
	if _, err := monitor.Lookup(context.Background(), "../not-a-domain"); err == nil {
		t.Fatal("invalid domain accepted")
	}
}
