package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/adaptive-trust/atc/internal/renewal"
)

func TestRenewalClientCarriesForwardExpectedState(t *testing.T) {
	want := []struct{ from, to string }{{"RENEWAL_PENDING", "ISSUING"}, {"ISSUING", "ISSUED"}}
	index := 0
	transport := roundTripper(func(r *http.Request) (*http.Response, error) {
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if index >= len(want) || body["from"] != want[index].from || body["to"] != want[index].to {
			t.Fatalf("transition %d = %#v", index, body)
		}
		index++
		return &http.Response{StatusCode: http.StatusNoContent, Status: "204 No Content", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	client := &RenewalClient{ServerURL: "http://atc.invalid", Token: "agent-token", JobID: "job-1", HTTPClient: &http.Client{Transport: transport}}
	if err := client.Record(context.Background(), renewal.Issuing); err != nil {
		t.Fatal(err)
	}
	if err := client.Record(context.Background(), renewal.Issued); err != nil {
		t.Fatal(err)
	}
	if index != len(want) {
		t.Fatalf("transitions=%d", index)
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
