package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/adaptive-trust/atc/internal/certificates"
	"github.com/adaptive-trust/atc/internal/issuer"
	"github.com/adaptive-trust/atc/internal/notify"
	"github.com/adaptive-trust/atc/internal/policy"
	"github.com/adaptive-trust/atc/internal/renewal"
	"github.com/adaptive-trust/atc/internal/risk"
	"github.com/adaptive-trust/atc/internal/storage"
)

type Server struct {
	store     storage.Repository
	bootstrap string
	operator  string
	log       *slog.Logger
	policy    policy.Policy
	issuer    issuer.CertificateIssuer
	notifier  notify.Notifier
	now       func() time.Time
	rules     []risk.VulnerabilityRule
}

func New(store storage.Repository, bootstrap string, log *slog.Logger) *Server {
	return &Server{store: store, bootstrap: bootstrap, log: log, policy: policy.Default(), now: time.Now}
}
func (s *Server) WithIssuer(value issuer.CertificateIssuer) *Server { s.issuer = value; return s }
func (s *Server) WithOperatorToken(value string) *Server            { s.operator = value; return s }
func (s *Server) WithNotifier(value notify.Notifier) *Server        { s.notifier = value; return s }
func (s *Server) WithPolicy(value policy.Policy) *Server {
	if err := value.Validate(); err == nil {
		s.policy = value
	}
	return s
}
func (s *Server) WithVulnerabilityRules(value []risk.VulnerabilityRule) *Server {
	s.rules = append([]risk.VulnerabilityRule(nil), value...)
	return s
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.dashboard)
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("POST /api/v1/agents/register", s.register)
	mux.HandleFunc("GET /api/v1/agents", s.agents)
	mux.HandleFunc("GET /api/v1/agents/{id}", s.agentDetail)
	mux.HandleFunc("POST /api/v1/agents/{id}/revoke", s.revokeAgent)
	mux.HandleFunc("GET /api/v1/assets", s.assets)
	mux.HandleFunc("GET /api/v1/assets/{id}", s.asset)
	mux.HandleFunc("GET /api/v1/certificates", s.certificates)
	mux.HandleFunc("GET /api/v1/certificates/{id}", s.certificate)
	mux.HandleFunc("GET /api/v1/findings", s.findings)
	mux.HandleFunc("POST /api/v1/certificates/{id}/renew", s.requestRenewal(false))
	mux.HandleFunc("POST /api/v1/certificates/{id}/rotate", s.requestRenewal(true))
	mux.HandleFunc("GET /api/v1/renewals", s.renewals)
	mux.HandleFunc("GET /api/v1/renewals/{id}", s.renewal)
	mux.HandleFunc("GET /api/v1/agent/renewals", s.agentRenewals)
	mux.HandleFunc("POST /api/v1/agent/renewals/{id}/state", s.agentRenewalState)
	mux.HandleFunc("POST /api/v1/agent/renewals/{id}/csr", s.agentCSR)
	mux.HandleFunc("GET /api/v1/audit", s.audit)
	mux.HandleFunc("POST /api/v1/inventory", s.inventory)
	return securityHeaders(mux)
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "version": "0.1.0"})
}

type registration struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.bootstrapAuthorized(r) {
		writeJSON(w, 401, map[string]string{"error": "bootstrap authorization required"})
		return
	}
	var x registration
	if !decode(w, r, &x) {
		return
	}
	a, t, err := s.store.Register(r.Context(), x.Name, x.Hostname, x.Version)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("agent registered", "agent_id", a.ID)
	writeJSON(w, 201, map[string]any{"agent": a, "agent_token": t})
}
func (s *Server) bootstrapAuthorized(r *http.Request) bool {
	if s.bootstrap == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.bootstrap)) == 1
}
func bearer(r *http.Request) string {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, p) {
		return strings.TrimPrefix(h, p)
	}
	return ""
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return false
	}
	return true
}
func (s *Server) agent(r *http.Request) (storage.Agent, bool) {
	a, ok, err := s.store.Authenticate(r.Context(), bearer(r))
	return a, ok && err == nil
}
func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Agents(r.Context())
	if err != nil {
		s.list(w, nil, err)
		return
	}
	observedAt := s.now().UTC()
	response := make([]agentView, 0, len(value))
	for _, agent := range value {
		response = append(response, agentView{ID: agent.ID, Name: agent.Name, Hostname: agent.Hostname, Version: agent.Version, Status: agent.Status, LastSeen: agent.LastSeen, InventoryStatus: inventoryStatus(agent.LastSeen, observedAt)})
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) agentDetail(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Agents(r.Context())
	if err != nil {
		s.list(w, nil, err)
		return
	}
	for _, agent := range value {
		if agent.ID == r.PathValue("id") {
			writeJSON(w, http.StatusOK, agentView{ID: agent.ID, Name: agent.Name, Hostname: agent.Hostname, Version: agent.Version, Status: agent.Status, LastSeen: agent.LastSeen, InventoryStatus: inventoryStatus(agent.LastSeen, s.now().UTC())})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
}

const staleInventoryAfter = 15 * time.Minute

type agentView struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Hostname        string    `json:"hostname"`
	Version         string    `json:"version"`
	Status          string    `json:"status"`
	LastSeen        time.Time `json:"last_seen"`
	InventoryStatus string    `json:"inventory_status"`
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) {
	authorized := s.bootstrapAuthorized(r)
	if s.operator != "" {
		authorized = s.operatorAuthorized(r)
	}
	if !authorized || r.Header.Get("X-ATC-Confirm") != "revoke" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "operator authorization and X-ATC-Confirm: revoke are required"})
		return
	}
	if err := s.store.RevokeAgent(r.Context(), r.PathValue("id")); err != nil {
		if err.Error() == "unknown agent" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		s.log.Error("agent revocation failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage unavailable"})
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func inventoryStatus(lastSeen, now time.Time) string {
	if lastSeen.IsZero() || lastSeen.After(now) {
		return "UNKNOWN"
	}
	if now.Sub(lastSeen) > staleInventoryAfter {
		return "STALE"
	}
	return "FRESH"
}
func (s *Server) assets(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Assets(r.Context())
	s.list(w, value, err)
}
func (s *Server) asset(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Assets(r.Context())
	if err != nil {
		s.list(w, nil, err)
		return
	}
	for _, asset := range value {
		if asset.ID == r.PathValue("id") {
			writeJSON(w, http.StatusOK, asset)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "asset not found"})
}
func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Certificates(r.Context())
	for index := range value {
		value[index] = s.currentPolicy(value[index])
	}
	s.list(w, value, err)
}
func (s *Server) certificate(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, found, err := s.store.Certificate(r.Context(), r.PathValue("id"))
	if err != nil {
		s.log.Error("certificate read failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage unavailable"})
		return
	}
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "certificate not found"})
		return
	}
	value = s.currentPolicy(value)
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) currentPolicy(certificate storage.Certificate) storage.Certificate {
	certificate.Policy = s.policy.Evaluate(certificate.Record.NotAfter, certificate.Record.SignatureAlgorithm, certificate.Record.PublicKeyBits, s.now().UTC())
	return certificate
}

type findingView struct {
	AssetID        string       `json:"asset_id"`
	Hostname       string       `json:"hostname"`
	OpenSSLVersion string       `json:"openssl_version"`
	Finding        risk.Finding `json:"finding"`
}

func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	assets, err := s.store.Assets(r.Context())
	if err != nil {
		s.list(w, nil, err)
		return
	}
	results := make([]findingView, 0)
	for _, asset := range assets {
		findings, err := risk.EvaluateOpenSSL(asset.OpenSSLVersion, s.rules)
		if err != nil {
			results = append(results, findingView{AssetID: asset.ID, Hostname: asset.Hostname, OpenSSLVersion: asset.OpenSSLVersion, Finding: risk.Finding{RuleID: "UNVERIFIABLE_OPENSSL_VERSION", Severity: "MEDIUM", Description: "Reported OpenSSL version cannot be evaluated", Evidence: asset.OpenSSLVersion}})
			continue
		}
		for _, finding := range findings {
			results = append(results, findingView{AssetID: asset.ID, Hostname: asset.Hostname, OpenSSLVersion: asset.OpenSSLVersion, Finding: finding})
		}
	}
	writeJSON(w, http.StatusOK, results)
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Audit(r.Context())
	s.list(w, value, err)
}
func (s *Server) renewals(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Renewals(r.Context())
	s.list(w, value, err)
}
func (s *Server) renewal(w http.ResponseWriter, r *http.Request) {
	if !s.requireOperator(w, r) {
		return
	}
	value, err := s.store.Renewals(r.Context())
	if err != nil {
		s.list(w, nil, err)
		return
	}
	for _, job := range value {
		if job.ID == r.PathValue("id") {
			writeJSON(w, http.StatusOK, job)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "renewal job not found"})
}
func (s *Server) agentRenewals(w http.ResponseWriter, r *http.Request) {
	a, ok := s.agent(r)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "agent authorization required"})
		return
	}
	commands, err := s.store.PendingRenewals(r.Context(), a.ID)
	s.list(w, commands, err)
}

type renewalStateRequest struct {
	From renewal.State `json:"from"`
	To   renewal.State `json:"to"`
}

func (s *Server) agentRenewalState(w http.ResponseWriter, r *http.Request) {
	a, ok := s.agent(r)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "agent authorization required"})
		return
	}
	var request renewalStateRequest
	if !decode(w, r, &request) {
		return
	}
	if err := s.store.AdvanceRenewal(r.Context(), a.ID, r.PathValue("id"), request.From, request.To); err != nil {
		status := http.StatusBadRequest
		if err.Error() == "renewal job is not assigned to this agent" {
			status = http.StatusForbidden
		}
		if err.Error() == "renewal state has changed" {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if renewalFailureState(request.To) {
		s.notify(notify.Event{
			Type:         "renewal_state_failed",
			Severity:     "HIGH",
			RenewalJobID: r.PathValue("id"),
			Message:      fmt.Sprintf("Renewal job entered %s", request.To),
		})
	}
	writeJSON(w, http.StatusNoContent, nil)
}

func renewalFailureState(state renewal.State) bool {
	return state == renewal.RenewalFailed || state == renewal.DeploymentFailed || state == renewal.ValidationFailed
}

type csrRequest struct {
	CSRPEM          string `json:"csr_pem"`
	LifetimeSeconds int64  `json:"lifetime_seconds"`
}

func (s *Server) agentCSR(w http.ResponseWriter, r *http.Request) {
	a, ok := s.agent(r)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "agent authorization required"})
		return
	}
	if s.issuer == nil {
		writeJSON(w, 503, map[string]string{"error": "no certificate issuer is configured"})
		return
	}
	if err := s.store.AuthorizeRenewal(r.Context(), a.ID, r.PathValue("id"), renewal.Issuing); err != nil {
		status := http.StatusConflict
		if err.Error() == "renewal job is not assigned to this agent" {
			status = http.StatusForbidden
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	var request csrRequest
	if !decode(w, r, &request) {
		return
	}
	if len(request.CSRPEM) > 128<<10 {
		writeJSON(w, 400, map[string]string{"error": "CSR exceeds 128 KiB"})
		return
	}
	result, err := s.issuer.Issue(r.Context(), issuer.CertificateRequest{CSRPEM: []byte(request.CSRPEM), Lifetime: time.Duration(request.LifetimeSeconds) * time.Second})
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "certificate issuance failed"})
		return
	}
	s.log.Info("certificate issued", "agent_id", a.ID, "renewal_job_id", r.PathValue("id"))
	writeJSON(w, 200, map[string]any{"certificate_pem": string(result.CertificatePEM), "chain_pem": string(result.ChainPEM), "not_after": result.NotAfter})
}
func (s *Server) list(w http.ResponseWriter, value any, err error) {
	if err != nil {
		s.log.Error("storage read failed", "error", err)
		writeJSON(w, 503, map[string]string{"error": "storage unavailable"})
		return
	}
	writeJSON(w, 200, value)
}

type inventory struct {
	Hostname                string                `json:"hostname"`
	OperatingSystem         string                `json:"operating_system"`
	OpenSSLVersion          string                `json:"openssl_version"`
	Certificates            []certificates.Record `json:"certificates"`
	RenewableCertificateIDs []string              `json:"renewable_certificate_ids"`
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request) {
	a, ok := s.agent(r)
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "agent authorization required"})
		return
	}
	var x inventory
	if !decode(w, r, &x) {
		return
	}
	asset, certs, err := s.store.Ingest(r.Context(), a.ID, x.Hostname, x.OperatingSystem, x.OpenSSLVersion, x.Certificates, x.RenewableCertificateIDs, s.policy)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	s.log.Info("inventory accepted", "agent_id", a.ID, "asset_id", asset.ID, "certificates", len(certs))
	s.notifyHighRiskInventory(asset.ID, certs)
	writeJSON(w, 202, map[string]any{"asset": asset, "certificates": certs})
}

func (s *Server) notifyHighRiskInventory(assetID string, certs []storage.Certificate) {
	count := 0
	critical := 0
	for _, certificate := range certs {
		switch certificate.Policy.Risk {
		case "CRITICAL":
			count++
			critical++
		case "HIGH":
			count++
		}
	}
	if count == 0 {
		return
	}
	severity := "HIGH"
	if critical > 0 {
		severity = "CRITICAL"
	}
	s.notify(notify.Event{
		Type:     "certificate_risk_detected",
		Severity: severity,
		AssetID:  assetID,
		Message:  fmt.Sprintf("Inventory reported %d high-risk certificate(s), including %d critical", count, critical),
	})
}

func (s *Server) notify(event notify.Event) {
	if s.notifier == nil {
		return
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = s.now().UTC()
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.notifier.Notify(ctx, event); err != nil {
			s.log.Error("alert delivery failed", "event_type", event.Type, "error", err)
		}
	}()
}
func (s *Server) requestRenewal(rotateKey bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authorized := s.bootstrapAuthorized(r)
		if s.operator != "" {
			authorized = s.operatorAuthorized(r)
		}
		if !authorized || r.Header.Get("X-ATC-Confirm") != "renewal" {
			writeJSON(w, 401, map[string]string{"error": "operator authorization and X-ATC-Confirm: renewal are required"})
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if !validIdempotencyKey(key) {
			writeJSON(w, 400, map[string]string{"error": "a 1-128 character Idempotency-Key using letters, digits, dot, underscore, or hyphen is required"})
			return
		}
		job, err := s.store.RequestRenewal(r.Context(), r.PathValue("id"), key, rotateKey)
		if err != nil {
			status := http.StatusBadRequest
			if err.Error() == "active renewal job already exists" {
				status = http.StatusConflict
			}
			writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, job)
	}
}
func (s *Server) operatorAuthorized(r *http.Request) bool {
	return s.operator != "" && subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.operator)) == 1
}
func (s *Server) requireOperator(w http.ResponseWriter, r *http.Request) bool {
	if s.operator == "" || s.operatorAuthorized(r) {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "operator authorization required"})
	return false
}
func validIdempotencyKey(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><title>ATC Security Dashboard</title><style>body{font:16px system-ui;margin:2rem;color:#172033}table{border-collapse:collapse;width:100%;margin-top:1rem}th,td{padding:.6rem;border:1px solid #d9d9d9;text-align:left}th{background:#172033;color:white}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{padding:1rem;background:#f3f6fa;border-radius:.5rem}form{margin:1rem 0}input{padding:.4rem;margin-left:.5rem}#error{color:#a40000}</style><h1>ATC Security Dashboard</h1><form id=auth><label>Operator token <input id=token type=password autocomplete=off></label><button>Load</button></form><p id=error></p><div class=cards><div class=card id=assets>Assets: 0</div><div class=card id=certs>Certificates: 0</div><div class=card id=risks>High risk: 0</div><div class=card id=stale>Stale inventories: 0</div><div class=card id=vulns>OpenSSL findings: 0</div></div><table><thead><tr><th>Subject</th><th>Issuer</th><th>Expires</th><th>Risk</th><th>Status</th></tr></thead><tbody id=rows></tbody></table><script>const form=document.getElementById('auth'),token=document.getElementById('token'),error=document.getElementById('error');token.value=sessionStorage.getItem('atcOperatorToken')||'';form.addEventListener('submit',e=>{e.preventDefault();load()});function api(path){const headers=token.value?{Authorization:'Bearer '+token.value}:{};return fetch(path,{headers}).then(r=>{if(!r.ok)throw Error(r.status===401?'Operator token required or invalid':'Request failed');return r.json()})}function load(){error.textContent='';sessionStorage.setItem('atcOperatorToken',token.value);Promise.all([api('/api/v1/certificates'),api('/api/v1/agents'),api('/api/v1/findings')]).then(([c,a,f])=>{assets.textContent='Assets: '+new Set(c.map(x=>x.AssetID)).size;certs.textContent='Certificates: '+c.length;risks.textContent='High risk: '+c.filter(x=>x.Policy.Risk==='HIGH'||x.Policy.Risk==='CRITICAL').length;stale.textContent='Stale inventories: '+a.filter(x=>x.inventory_status==='STALE'||x.inventory_status==='UNKNOWN').length;vulns.textContent='OpenSSL findings: '+f.length;rows.innerHTML=c.map(x=>'<tr><td>'+esc(x.Record.Subject)+'</td><td>'+esc(x.Record.Issuer)+'</td><td>'+new Date(x.Record.NotAfter).toLocaleString()+'</td><td>'+esc(x.Policy.Risk)+'</td><td>'+esc(x.Policy.Status)+'</td></tr>').join('')}).catch(e=>error.textContent=e.message)}load();function esc(s){const e=document.createElement('span');e.textContent=s;return e.innerHTML}</script>`))
}
