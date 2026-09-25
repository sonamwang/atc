package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/adaptive-trust/atc/internal/certificates"
	"github.com/adaptive-trust/atc/internal/policy"
	"github.com/adaptive-trust/atc/internal/renewal"
	"github.com/adaptive-trust/atc/internal/retry"
)

type Agent struct {
	ID, Name, Hostname, Version, Status string
	LastSeen                            time.Time
}
type Asset struct {
	ID, AgentID, Hostname, OS, OpenSSLVersion string
	UpdatedAt                                 time.Time
}
type Certificate struct {
	ID, AssetID       string
	Record            certificates.Record
	Policy            policy.Result
	AutoRenewEligible bool `json:"auto_renew_eligible"`
	UpdatedAt         time.Time
}
type AuditEvent struct {
	ID, EventType, ActorID, AssetID, CertificateID, Severity, Message string
	CreatedAt                                                         time.Time
}
type RenewalJob struct {
	ID, CertificateID, IdempotencyKey, Status string
	RotateKey                                 bool
	RequestedAt                               time.Time
	AttemptCount                              int
	NextAttemptAt                             *time.Time
}

// RenewalCommand contains only public certificate metadata required by an
// authenticated owning agent. It never contains a private key or token.
type RenewalCommand struct {
	Job             RenewalJob
	CertificatePath string
	DNSNames        []string
}

// Repository defines the persistence required by the inventory control plane.
// It exposes no mutation method for audit events.
type Repository interface {
	Register(context.Context, string, string, string) (Agent, string, error)
	Authenticate(context.Context, string) (Agent, bool, error)
	RevokeAgent(context.Context, string) error
	Ingest(context.Context, string, string, string, string, []certificates.Record, []string, policy.Policy) (Asset, []Certificate, error)
	Agents(context.Context) ([]Agent, error)
	Assets(context.Context) ([]Asset, error)
	Certificates(context.Context) ([]Certificate, error)
	Certificate(context.Context, string) (Certificate, bool, error)
	Audit(context.Context) ([]AuditEvent, error)
	RequestRenewal(context.Context, string, string, bool) (RenewalJob, error)
	Renewals(context.Context) ([]RenewalJob, error)
	PendingRenewals(context.Context, string) ([]RenewalCommand, error)
	AdvanceRenewal(context.Context, string, string, renewal.State, renewal.State) error
	AuthorizeRenewal(context.Context, string, string, renewal.State) error
	RequeueRenewals(context.Context, time.Time) (int, error)
	EnqueueExpiringRenewals(context.Context, time.Time, policy.Policy) (int, error)
	Close()
}

// Memory is deliberately for local development and tests only.
type Memory struct {
	mu     sync.RWMutex
	agents map[string]Agent
	tokens map[[32]byte]string
	assets map[string]Asset
	certs  map[string]Certificate
	audit  []AuditEvent
	jobs   map[string]RenewalJob
}

func NewMemory() *Memory {
	return &Memory{agents: map[string]Agent{}, tokens: map[[32]byte]string{}, assets: map[string]Asset{}, certs: map[string]Certificate{}, jobs: map[string]RenewalJob{}}
}

func id(prefix string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
func certificateID(assetID, path string) string {
	digest := sha256.Sum256([]byte(assetID + "\x00" + path))
	return "cert_" + hex.EncodeToString(digest[:])
}
func token() (string, [32]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", [32]byte{}, err
	}
	s := hex.EncodeToString(b)
	return s, sha256.Sum256([]byte(s)), nil
}

func (s *Memory) Register(_ context.Context, name, hostname, version string) (Agent, string, error) {
	if name == "" || hostname == "" {
		return Agent{}, "", errors.New("name and hostname are required")
	}
	t, hash, err := token()
	if err != nil {
		return Agent{}, "", err
	}
	a := Agent{ID: id("agt"), Name: name, Hostname: hostname, Version: version, Status: "ACTIVE", LastSeen: time.Now().UTC()}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[a.ID] = a
	s.tokens[hash] = a.ID
	s.audit = append(s.audit, event("agent_registered", a.ID, "", "", "INFO", "Agent enrolled"))
	return a, t, nil
}
func (s *Memory) Authenticate(_ context.Context, raw string) (Agent, bool, error) {
	h := sha256.Sum256([]byte(raw))
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.tokens[h]
	a, exists := s.agents[id]
	return a, ok && exists && a.Status == "ACTIVE", nil
}
func (s *Memory) RevokeAgent(_ context.Context, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok {
		return errors.New("unknown agent")
	}
	if agent.Status == "REVOKED" {
		return nil
	}
	agent.Status = "REVOKED"
	s.agents[agentID] = agent
	s.audit = append(s.audit, event("agent_revoked", "operator", "", "", "HIGH", "Agent credential revoked"))
	return nil
}
func (s *Memory) Ingest(_ context.Context, agentID, hostname, os, opensslVersion string, records []certificates.Record, renewableCertificateIDs []string, p policy.Policy) (Asset, []Certificate, error) {
	if hostname == "" {
		return Asset{}, nil, errors.New("hostname is required")
	}
	now := time.Now().UTC()
	for index := range records {
		if records[index].ChainLength == 0 {
			records[index].ChainLength = 1
		}
		if records[index].DiscoveredAt.IsZero() {
			records[index].DiscoveredAt = now
		}
		if err := certificates.ValidateRecord(records[index]); err != nil {
			return Asset{}, nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	agent, ok := s.agents[agentID]
	if !ok || agent.Status != "ACTIVE" {
		return Asset{}, nil, errors.New("unknown agent")
	}
	a := Asset{ID: "asset_" + agentID, AgentID: agentID, Hostname: hostname, OS: os, OpenSSLVersion: opensslVersion, UpdatedAt: now}
	s.assets[a.ID] = a
	agent = s.agents[agentID]
	agent.LastSeen = now
	s.agents[agentID] = agent
	certs := make([]Certificate, 0, len(records))
	eligible := make(map[string]struct{}, len(renewableCertificateIDs))
	for _, certificateID := range renewableCertificateIDs {
		eligible[certificateID] = struct{}{}
	}
	for _, r := range records {
		stableID := certificateID(a.ID, r.Path)
		_, autoRenewEligible := eligible[stableID]
		c := Certificate{ID: stableID, AssetID: a.ID, Record: r, Policy: p.Evaluate(r.NotAfter, r.SignatureAlgorithm, r.PublicKeyBits, now), AutoRenewEligible: autoRenewEligible, UpdatedAt: now}
		s.certs[c.ID] = c
		certs = append(certs, c)
		s.audit = append(s.audit, event("certificate_discovered", agentID, a.ID, c.ID, c.Policy.Risk, c.Policy.Reason))
	}
	s.audit = append(s.audit, event("inventory_received", agentID, a.ID, "", "INFO", "Certificate inventory received"))
	return a, certs, nil
}
func event(kind, actor, asset, cert, severity, message string) AuditEvent {
	return AuditEvent{ID: id("audit"), EventType: kind, ActorID: actor, AssetID: asset, CertificateID: cert, Severity: severity, Message: message, CreatedAt: time.Now().UTC()}
}
func (s *Memory) Agents(_ context.Context) ([]Agent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Agent, 0, len(s.agents))
	for _, v := range s.agents {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *Memory) Assets(_ context.Context) ([]Asset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Asset, 0, len(s.assets))
	for _, v := range s.assets {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *Memory) Certificates(_ context.Context) ([]Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Certificate, 0, len(s.certs))
	now := time.Now().UTC()
	for _, v := range s.certs {
		out = append(out, currentPolicy(v, now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (s *Memory) Certificate(_ context.Context, certificateID string) (Certificate, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	certificate, ok := s.certs[certificateID]
	return currentPolicy(certificate, time.Now().UTC()), ok, nil
}

func currentPolicy(certificate Certificate, now time.Time) Certificate {
	certificate.Policy = policy.Default().Evaluate(certificate.Record.NotAfter, certificate.Record.SignatureAlgorithm, certificate.Record.PublicKeyBits, now)
	return certificate
}
func (s *Memory) Audit(_ context.Context) ([]AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]AuditEvent(nil), s.audit...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Memory) RequestRenewal(_ context.Context, certificateID, idempotencyKey string, rotateKey bool) (RenewalJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.certs[certificateID]; !ok {
		return RenewalJob{}, errors.New("unknown certificate")
	}
	for _, job := range s.jobs {
		if job.IdempotencyKey == idempotencyKey {
			if job.CertificateID != certificateID || job.RotateKey != rotateKey {
				return RenewalJob{}, errors.New("idempotency key was used for another request")
			}
			return job, nil
		}
	}
	for _, job := range s.jobs {
		if job.CertificateID == certificateID && job.Status == "RENEWAL_PENDING" {
			return RenewalJob{}, errors.New("active renewal job already exists")
		}
	}
	job := RenewalJob{ID: id("renewal"), CertificateID: certificateID, IdempotencyKey: idempotencyKey, Status: "RENEWAL_PENDING", RotateKey: rotateKey, RequestedAt: time.Now().UTC()}
	s.jobs[job.ID] = job
	s.audit = append(s.audit, event("certificate_renewal_requested", "operator", "", certificateID, "INFO", "Certificate renewal requested"))
	return job, nil
}

func (s *Memory) Renewals(_ context.Context) ([]RenewalJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RenewalJob, 0, len(s.jobs))
	for _, job := range s.jobs {
		out = append(out, job)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	return out, nil
}
func (s *Memory) PendingRenewals(_ context.Context, agentID string) ([]RenewalCommand, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []RenewalCommand{}
	for _, job := range s.jobs {
		if job.Status != string(renewal.RenewalPending) {
			continue
		}
		cert, ok := s.certs[job.CertificateID]
		if !ok {
			continue
		}
		asset, ok := s.assets[cert.AssetID]
		if !ok || asset.AgentID != agentID {
			continue
		}
		out = append(out, RenewalCommand{Job: job, CertificatePath: cert.Record.Path, DNSNames: append([]string{}, cert.Record.SANs...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Job.RequestedAt.Before(out[j].Job.RequestedAt) })
	return out, nil
}
func (s *Memory) AdvanceRenewal(_ context.Context, agentID, jobID string, from, to renewal.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return errors.New("unknown renewal job")
	}
	cert, ok := s.certs[job.CertificateID]
	if !ok {
		return errors.New("unknown certificate")
	}
	asset, ok := s.assets[cert.AssetID]
	if !ok || asset.AgentID != agentID {
		return errors.New("renewal job is not assigned to this agent")
	}
	if job.Status != string(from) {
		return errors.New("renewal state has changed")
	}
	if err := renewal.Transition(from, to); err != nil {
		return err
	}
	job.Status = string(to)
	if to == renewal.RenewalFailed {
		job.AttemptCount++
		delay, err := retry.Default().Delay(job.AttemptCount, nil)
		if err == nil {
			next := time.Now().UTC().Add(delay)
			job.NextAttemptAt = &next
		}
	}
	s.jobs[job.ID] = job
	s.audit = append(s.audit, event("renewal_state_changed", agentID, asset.ID, cert.ID, "INFO", string(to)))
	return nil
}
func (s *Memory) RequeueRenewals(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for id, job := range s.jobs {
		if job.Status != string(renewal.RenewalFailed) || job.NextAttemptAt == nil || job.NextAttemptAt.After(now) {
			continue
		}
		if job.AttemptCount >= retry.Default().MaxAttempts {
			continue
		}
		job.Status = string(renewal.RenewalPending)
		job.NextAttemptAt = nil
		s.jobs[id] = job
		s.audit = append(s.audit, event("certificate_renewal_requeued", "scheduler", "", job.CertificateID, "INFO", "Renewal retry is due"))
		count++
	}
	return count, nil
}
func (s *Memory) EnqueueExpiringRenewals(_ context.Context, now time.Time, p policy.Policy) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, certificate := range s.certs {
		if !certificate.AutoRenewEligible {
			continue
		}
		current := p.Evaluate(certificate.Record.NotAfter, certificate.Record.SignatureAlgorithm, certificate.Record.PublicKeyBits, now)
		if current.Status != "EXPIRING" && current.Status != "EXPIRED" {
			continue
		}
		requestedForSnapshot := false
		for _, job := range s.jobs {
			if job.CertificateID == certificate.ID && !job.RequestedAt.Before(certificate.UpdatedAt) {
				requestedForSnapshot = true
				break
			}
		}
		if requestedForSnapshot {
			continue
		}
		job := RenewalJob{ID: id("renewal"), CertificateID: certificate.ID, IdempotencyKey: "auto-" + certificate.ID + "-" + fmt.Sprint(certificate.UpdatedAt.Unix()), Status: "RENEWAL_PENDING", RequestedAt: now}
		s.jobs[job.ID] = job
		s.audit = append(s.audit, event("certificate_renewal_auto_requested", "scheduler", certificate.AssetID, certificate.ID, current.Risk, current.Reason))
		count++
	}
	return count, nil
}
func (s *Memory) AuthorizeRenewal(_ context.Context, agentID, jobID string, expected renewal.State) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.jobs[jobID]
	if !ok {
		return errors.New("unknown renewal job")
	}
	cert, ok := s.certs[job.CertificateID]
	if !ok {
		return errors.New("unknown certificate")
	}
	asset, ok := s.assets[cert.AssetID]
	if !ok || asset.AgentID != agentID {
		return errors.New("renewal job is not assigned to this agent")
	}
	if job.Status != string(expected) {
		return errors.New("renewal state has changed")
	}
	return nil
}

func (s *Memory) Close() {}
