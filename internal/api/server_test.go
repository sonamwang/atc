package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/adaptive-trust/atc/internal/auth"
	"github.com/adaptive-trust/atc/internal/ct"
	"github.com/adaptive-trust/atc/internal/notify"
	"github.com/adaptive-trust/atc/internal/policy"
	"github.com/adaptive-trust/atc/internal/risk"
	"github.com/adaptive-trust/atc/internal/storage"
)

type recordingNotifier struct{ events chan notify.Event }

func (notifier recordingNotifier) Notify(ctx context.Context, event notify.Event) error {
	select {
	case notifier.events <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func nextAlert(t *testing.T, notifier recordingNotifier) notify.Event {
	t.Helper()
	select {
	case event := <-notifier.events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for alert")
		return notify.Event{}
	}
}

func TestInventoryRequiresAgentTokenAndUsesAuthenticatedAgent(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	bad := request(t, h, http.MethodPost, "/api/v1/inventory", "", map[string]any{"hostname": "host"})
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated inventory = %d", bad.Code)
	}
	reg := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	if reg.Code != http.StatusCreated {
		t.Fatalf("register = %d: %s", reg.Code, reg.Body.String())
	}
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&enrolled)
	inv := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, inventoryPayload("/etc/ssl/a.pem", "a", nil))
	if inv.Code != http.StatusAccepted {
		t.Fatalf("inventory = %d: %s", inv.Code, inv.Body.String())
	}
	malformed := inventoryPayload("relative.pem", "e", nil)
	badShape := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, malformed)
	if badShape.Code != http.StatusBadRequest {
		t.Fatalf("malformed inventory = %d: %s", badShape.Code, badShape.Body.String())
	}
}

func TestNotifierReportsHighRiskInventoryWithoutCertificateDetails(t *testing.T) {
	notifier := recordingNotifier{events: make(chan notify.Event, 1)}
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).WithNotifier(notifier).Handler()
	registration := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(registration.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	inventory := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, inventoryPayload("/a.pem", "a", nil))
	if inventory.Code != http.StatusAccepted {
		t.Fatalf("inventory = %d: %s", inventory.Code, inventory.Body.String())
	}
	event := nextAlert(t, notifier)
	if event.Type != "certificate_risk_detected" || event.Severity != "CRITICAL" || event.AssetID == "" || event.CertificateID != "" || !strings.Contains(event.Message, "1 high-risk") {
		t.Fatalf("unexpected risk alert: %#v", event)
	}
}

func TestRegistrationRejectsTrailingJSON(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agents/register", bytes.NewBufferString(`{"name":"agent","hostname":"host","version":"test"} {"name":"second"}`))
	r.Header.Set("Authorization", "Bearer bootstrap")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON = %d: %s", w.Code, w.Body.String())
	}
}

func TestInventoryStatusReflectsFreshness(t *testing.T) {
	timeNow := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	if status := inventoryStatus(timeNow.Add(-staleInventoryAfter), timeNow); status != "FRESH" {
		t.Fatalf("cutoff inventory status = %s", status)
	}
	if status := inventoryStatus(timeNow.Add(-staleInventoryAfter-time.Second), timeNow); status != "STALE" {
		t.Fatalf("old inventory status = %s", status)
	}
	if status := inventoryStatus(timeNow.Add(time.Second), timeNow); status != "UNKNOWN" {
		t.Fatalf("future inventory status = %s", status)
	}
}

func TestFindingsEvaluateReportedOpenSSLVersion(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).WithVulnerabilityRules([]risk.VulnerabilityRule{{ID: "EXAMPLE-1", Product: "openssl", Severity: "HIGH", Description: "example", Affected: []risk.VersionRange{{Minimum: "1.1.1a", Maximum: "1.1.1m"}}, References: []string{"https://example.test/advisory"}}}).Handler()
	reg := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&enrolled)
	payload := inventoryPayload("/a.pem", "f", nil)
	payload["openssl_version"] = "OpenSSL 1.1.1k  25 Mar 2021"
	inv := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, payload)
	if inv.Code != http.StatusAccepted {
		t.Fatalf("inventory = %d: %s", inv.Code, inv.Body.String())
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil))
	if out.Code != http.StatusOK {
		t.Fatalf("findings = %d: %s", out.Code, out.Body.String())
	}
	var findings []findingView
	if err := json.NewDecoder(out.Body).Decode(&findings); err != nil || len(findings) != 1 || findings[0].Finding.RuleID != "EXAMPLE-1" {
		t.Fatalf("findings = %#v, %v", findings, err)
	}
}

func TestDashboardIncludesOpenSSLFindingSummary(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	out := httptest.NewRecorder()
	h.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/", nil))
	if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), "OpenSSL findings") {
		t.Fatalf("dashboard response = %d: %s", out.Code, out.Body.String())
	}
}

func TestOperatorTokenProtectsOperatorEndpoints(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).WithOperatorToken("operator").Handler()
	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized certificate list = %d", unauthorized.Code)
	}
	authorizedRequest := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	authorizedRequest.Header.Set("Authorization", "Bearer operator")
	authorized := httptest.NewRecorder()
	h.ServeHTTP(authorized, authorizedRequest)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized certificate list = %d: %s", authorized.Code, authorized.Body.String())
	}
}

func TestRBACSeparatesViewerOperatorAndAdmin(t *testing.T) {
	authorizer, err := auth.NewOperatorAuthorizer([]auth.Credential{
		{Name: "viewer", Role: auth.RoleViewer, Token: "viewer-token-for-api"},
		{Name: "operator", Role: auth.RoleOperator, Token: "operator-token-for-api"},
		{Name: "admin", Role: auth.RoleAdmin, Token: "admin-token-for-api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := New(storage.NewMemory(), "bootstrap", slog.Default()).WithOperatorAuthorizer(authorizer)
	h := server.Handler()
	viewerRead := httptest.NewRequest(http.MethodGet, "/api/v1/certificates", nil)
	viewerRead.Header.Set("Authorization", "Bearer viewer-token-for-api")
	viewerResult := httptest.NewRecorder()
	h.ServeHTTP(viewerResult, viewerRead)
	if viewerResult.Code != http.StatusOK {
		t.Fatalf("viewer read = %d: %s", viewerResult.Code, viewerResult.Body.String())
	}
	viewerRenew := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/cert_missing/renew", nil)
	viewerRenew.Header.Set("Authorization", "Bearer viewer-token-for-api")
	viewerRenew.Header.Set("X-ATC-Confirm", "renewal")
	viewerRenew.Header.Set("Idempotency-Key", "rbac-viewer-001")
	viewerRenewResult := httptest.NewRecorder()
	h.ServeHTTP(viewerRenewResult, viewerRenew)
	if viewerRenewResult.Code != http.StatusForbidden {
		t.Fatalf("viewer renew = %d", viewerRenewResult.Code)
	}
	operatorRevoke := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agt_missing/revoke", nil)
	operatorRevoke.Header.Set("Authorization", "Bearer operator-token-for-api")
	operatorRevoke.Header.Set("X-ATC-Confirm", "revoke")
	operatorRevokeResult := httptest.NewRecorder()
	h.ServeHTTP(operatorRevokeResult, operatorRevoke)
	if operatorRevokeResult.Code != http.StatusForbidden {
		t.Fatalf("operator revoke = %d", operatorRevokeResult.Code)
	}
	whoami := httptest.NewRequest(http.MethodGet, "/api/v1/whoami", nil)
	whoami.Header.Set("Authorization", "Bearer admin-token-for-api")
	whoamiResult := httptest.NewRecorder()
	h.ServeHTTP(whoamiResult, whoami)
	if whoamiResult.Code != http.StatusOK || !strings.Contains(whoamiResult.Body.String(), `"name":"admin"`) {
		t.Fatalf("whoami = %d: %s", whoamiResult.Code, whoamiResult.Body.String())
	}
}

func TestCTLookupIsOptIn(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/ct/api.example.test", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured CT lookup = %d: %s", response.Code, response.Body.String())
	}
	// The API package only owns access control and response behaviour. Detailed
	// CT response parsing is covered in internal/ct tests.
	if _, err := ct.NewMonitor("https://ct.example.test/?q={domain}&output=json"); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorCanRevokeAgentCredential(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).WithOperatorToken("operator").Handler()
	registration := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		Agent struct {
			ID string `json:"ID"`
		} `json:"agent"`
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(registration.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	revoke := httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+enrolled.Agent.ID+"/revoke", nil)
	revoke.Header.Set("Authorization", "Bearer operator")
	revoke.Header.Set("X-ATC-Confirm", "revoke")
	revoked := httptest.NewRecorder()
	h.ServeHTTP(revoked, revoke)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d: %s", revoked.Code, revoked.Body.String())
	}
	inventory := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, inventoryPayload("/a.pem", "a", nil))
	if inventory.Code != http.StatusUnauthorized {
		t.Fatalf("revoked inventory = %d", inventory.Code)
	}
}

func TestRenewalRequestRequiresConfirmationAndIsIdempotent(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	reg := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&enrolled)
	inv := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, inventoryPayload("/a.pem", "b", nil))
	if inv.Code != http.StatusAccepted {
		t.Fatalf("inventory = %d", inv.Code)
	}
	certificateID := inventoryCertificateID(t, inv)
	create := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/"+certificateID+"/renew", nil)
		r.Header.Set("Authorization", "Bearer bootstrap")
		r.Header.Set("X-ATC-Confirm", "renewal")
		r.Header.Set("Idempotency-Key", "request-001")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if first := create(); first.Code != http.StatusAccepted {
		t.Fatalf("renewal = %d: %s", first.Code, first.Body.String())
	}
	if second := create(); second.Code != http.StatusAccepted {
		t.Fatalf("idempotent renewal = %d: %s", second.Code, second.Body.String())
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/"+certificateID+"/renew", nil)
	r.Header.Set("Authorization", "Bearer bootstrap")
	r.Header.Set("Idempotency-Key", "request-002")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unconfirmed renewal = %d", w.Code)
	}
}

func TestCertificateInspectionReturnsOneCertificateOrNotFound(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	reg := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&enrolled)
	inv := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, inventoryPayload("/a.pem", "c", nil))
	certificateID := inventoryCertificateID(t, inv)
	get := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/"+certificateID, nil)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, get)
	if out.Code != http.StatusOK {
		t.Fatalf("inspect = %d: %s", out.Code, out.Body.String())
	}
	var certificate storage.Certificate
	if err := json.NewDecoder(out.Body).Decode(&certificate); err != nil || certificate.ID != certificateID {
		t.Fatalf("inspect response = %#v, %v", certificate, err)
	}
	missing := httptest.NewRequest(http.MethodGet, "/api/v1/certificates/cert_missing", nil)
	missingOut := httptest.NewRecorder()
	h.ServeHTTP(missingOut, missing)
	if missingOut.Code != http.StatusNotFound {
		t.Fatalf("missing inspect = %d", missingOut.Code)
	}
}

func TestCertificateReadsUseConfiguredPolicy(t *testing.T) {
	configuredPolicy := policy.Policy{CriticalHours: 1, HighDays: 1, MediumDays: 3}
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).WithPolicy(configuredPolicy).Handler()
	registration := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(registration.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	payload := inventoryPayload("/a.pem", "e", nil)
	payload["certificates"].([]map[string]any)[0]["not_after"] = time.Now().Add(48 * time.Hour)
	accepted := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, payload)
	certificateID := inventoryCertificateID(t, accepted)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/certificates/"+certificateID, nil))
	var certificate storage.Certificate
	if err := json.NewDecoder(response.Body).Decode(&certificate); err != nil || response.Code != http.StatusOK || certificate.Policy.Risk != "MEDIUM" {
		t.Fatalf("configured policy response = %#v, status=%d, err=%v", certificate, response.Code, err)
	}
}

func TestResourceDetailEndpointsReturnOnlyRequestedRecord(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	registration := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		Agent struct {
			ID string `json:"ID"`
		} `json:"agent"`
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(registration.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	inventory := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, inventoryPayload("/a.pem", "e", nil))
	var inventoryResult struct {
		Asset        storage.Asset `json:"asset"`
		Certificates []struct {
			ID string `json:"ID"`
		} `json:"certificates"`
	}
	if err := json.NewDecoder(inventory.Body).Decode(&inventoryResult); err != nil {
		t.Fatal(err)
	}
	if len(inventoryResult.Certificates) != 1 || inventoryResult.Certificates[0].ID == "" {
		t.Fatalf("unexpected inventory result: %#v", inventoryResult)
	}
	certificateID := inventoryResult.Certificates[0].ID
	create := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/"+certificateID+"/renew", nil)
	create.Header.Set("Authorization", "Bearer bootstrap")
	create.Header.Set("X-ATC-Confirm", "renewal")
	create.Header.Set("Idempotency-Key", "detail-endpoints-001")
	created := httptest.NewRecorder()
	h.ServeHTTP(created, create)
	var job storage.RenewalJob
	if err := json.NewDecoder(created.Body).Decode(&job); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/agents/" + enrolled.Agent.ID, "/api/v1/assets/" + inventoryResult.Asset.ID, "/api/v1/renewals/" + job.ID} {
		response := httptest.NewRecorder()
		h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("detail %s = %d: %s", path, response.Code, response.Body.String())
		}
	}
	missing := httptest.NewRecorder()
	h.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/v1/renewals/renewal_missing", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing renewal = %d", missing.Code)
	}
}

func TestAgentCanReadAndAdvanceOnlyItsRenewal(t *testing.T) {
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).Handler()
	reg := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	_ = json.NewDecoder(reg.Body).Decode(&enrolled)
	inv := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, inventoryPayload("/a.pem", "d", []string{"api.example.test"}))
	if inv.Code != http.StatusAccepted {
		t.Fatal(inv.Code)
	}
	certificateID := inventoryCertificateID(t, inv)
	create := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/"+certificateID+"/renew", nil)
	create.Header.Set("Authorization", "Bearer bootstrap")
	create.Header.Set("X-ATC-Confirm", "renewal")
	create.Header.Set("Idempotency-Key", "agent-job-001")
	createOut := httptest.NewRecorder()
	h.ServeHTTP(createOut, create)
	if createOut.Code != http.StatusAccepted {
		t.Fatalf("create=%d", createOut.Code)
	}
	var job storage.RenewalJob
	_ = json.NewDecoder(createOut.Body).Decode(&job)
	poll := httptest.NewRequest(http.MethodGet, "/api/v1/agent/renewals", nil)
	poll.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	pollOut := httptest.NewRecorder()
	h.ServeHTTP(pollOut, poll)
	if pollOut.Code != http.StatusOK {
		t.Fatalf("poll=%d", pollOut.Code)
	}
	body, _ := json.Marshal(map[string]string{"from": "RENEWAL_PENDING", "to": "ISSUING"})
	advance := httptest.NewRequest(http.MethodPost, "/api/v1/agent/renewals/"+job.ID+"/state", bytes.NewReader(body))
	advance.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	advance.Header.Set("Content-Type", "application/json")
	advanceOut := httptest.NewRecorder()
	h.ServeHTTP(advanceOut, advance)
	if advanceOut.Code != http.StatusNoContent {
		t.Fatalf("advance=%d: %s", advanceOut.Code, advanceOut.Body.String())
	}
}

func TestNotifierReportsFailedRenewalState(t *testing.T) {
	notifier := recordingNotifier{events: make(chan notify.Event, 1)}
	h := New(storage.NewMemory(), "bootstrap", slog.Default()).WithNotifier(notifier).Handler()
	registration := request(t, h, http.MethodPost, "/api/v1/agents/register", "bootstrap", map[string]string{"name": "agent", "hostname": "host", "version": "test"})
	var enrolled struct {
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(registration.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	payload := inventoryPayload("/a.pem", "d", nil)
	payload["certificates"].([]map[string]any)[0]["not_after"] = time.Now().Add(90 * 24 * time.Hour)
	inventory := request(t, h, http.MethodPost, "/api/v1/inventory", enrolled.AgentToken, payload)
	certificateID := inventoryCertificateID(t, inventory)
	create := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/"+certificateID+"/renew", nil)
	create.Header.Set("Authorization", "Bearer bootstrap")
	create.Header.Set("X-ATC-Confirm", "renewal")
	create.Header.Set("Idempotency-Key", "alert-job-001")
	created := httptest.NewRecorder()
	h.ServeHTTP(created, create)
	var job storage.RenewalJob
	if err := json.NewDecoder(created.Body).Decode(&job); err != nil || job.ID == "" {
		t.Fatalf("renewal creation = %d, job=%#v, err=%v", created.Code, job, err)
	}
	advanceRenewalState(t, h, enrolled.AgentToken, job.ID, "RENEWAL_PENDING", "ISSUING")
	advanceRenewalState(t, h, enrolled.AgentToken, job.ID, "ISSUING", "RENEWAL_FAILED")
	event := nextAlert(t, notifier)
	if event.Type != "renewal_state_failed" || event.Severity != "HIGH" || event.RenewalJobID != job.ID || !strings.Contains(event.Message, "RENEWAL_FAILED") {
		t.Fatalf("unexpected renewal alert: %#v", event)
	}
}

func advanceRenewalState(t *testing.T, h http.Handler, token, jobID, from, to string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"from": from, "to": to})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/renewals/"+jobID+"/state", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("advance %s to %s = %d: %s", from, to, response.Code, response.Body.String())
	}
}
func inventoryCertificateID(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct{ Certificates []struct{ ID string } }
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Certificates) != 1 || body.Certificates[0].ID == "" {
		t.Fatalf("unexpected inventory response: %#v", body)
	}
	return body.Certificates[0].ID
}
func request(t *testing.T, h http.Handler, method, path, token string, payload any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(payload)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func inventoryPayload(path, fingerprintCharacter string, sans []string) map[string]any {
	return map[string]any{"hostname": "host", "operating_system": "linux", "certificates": []map[string]any{{"path": path, "subject": "CN=example", "issuer": "CN=test", "serial_number": "1", "not_before": time.Now().Add(-time.Hour), "not_after": time.Now().Add(time.Hour), "signature_algorithm": "SHA256-RSA", "public_key_algorithm": "RSA", "public_key_bits": 2048, "fingerprint_sha256": strings.Repeat(fingerprintCharacter, 64), "sans": sans}}}
}
