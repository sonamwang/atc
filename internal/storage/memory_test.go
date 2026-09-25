package storage

import (
	"context"
	"testing"
	"time"

	"github.com/adaptive-trust/atc/internal/certificates"
	"github.com/adaptive-trust/atc/internal/policy"
	"github.com/adaptive-trust/atc/internal/renewal"
)

func TestFailedRenewalIsRequeuedAfterBoundedDelay(t *testing.T) {
	store := NewMemory()
	agent, _, err := store.Register(context.Background(), "agent", "host", "test")
	if err != nil {
		t.Fatal(err)
	}
	_, certs, err := store.Ingest(context.Background(), agent.ID, "host", "linux", "", []certificates.Record{{Path: "/etc/ssl/a.pem", Subject: "CN=example", Issuer: "CN=test", SerialNumber: "1", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), SignatureAlgorithm: "SHA256-RSA", PublicKeyAlgorithm: "RSA", PublicKeyBits: 2048, FingerprintSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, nil, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	job, err := store.RequestRenewal(context.Background(), certs[0].ID, "retry-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRenewal(context.Background(), agent.ID, job.ID, renewal.RenewalPending, renewal.Issuing); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceRenewal(context.Background(), agent.ID, job.ID, renewal.Issuing, renewal.RenewalFailed); err != nil {
		t.Fatal(err)
	}
	count, err := store.RequeueRenewals(context.Background(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("requeued=%d", count)
	}
	jobs, err := store.Renewals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if jobs[0].Status != string(renewal.RenewalPending) {
		t.Fatalf("status=%s", jobs[0].Status)
	}
}

func TestCertificatePolicyIsEvaluatedWhenRead(t *testing.T) {
	store := NewMemory()
	store.certs["cert_example"] = Certificate{ID: "cert_example", Record: certificates.Record{NotAfter: time.Now().Add(-time.Minute), SignatureAlgorithm: "SHA256-RSA", PublicKeyBits: 2048}}
	certificate, found, err := store.Certificate(context.Background(), "cert_example")
	if err != nil || !found {
		t.Fatalf("certificate lookup = found %t, err %v", found, err)
	}
	if certificate.Policy.Status != "EXPIRED" || certificate.Policy.Risk != "CRITICAL" || certificate.Policy.Reason == "" {
		t.Fatalf("current policy = %#v", certificate.Policy)
	}
}

func TestRevokedAgentCannotAuthenticateOrIngest(t *testing.T) {
	store := NewMemory()
	agent, token, err := store.Register(context.Background(), "agent", "host", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeAgent(context.Background(), agent.ID); err != nil {
		t.Fatal(err)
	}
	if _, authenticated, err := store.Authenticate(context.Background(), token); err != nil || authenticated {
		t.Fatalf("revoked authentication = %t, %v", authenticated, err)
	}
	if _, _, err := store.Ingest(context.Background(), agent.ID, "host", "linux", "", nil, nil, policy.Default()); err == nil {
		t.Fatal("revoked agent inventory accepted")
	}
	agents, err := store.Agents(context.Background())
	if err != nil || agents[0].Status != "REVOKED" {
		t.Fatalf("agent status = %#v, %v", agents, err)
	}
}

func TestExpiringCertificateCreatesOneAutomaticRenewalPerInventorySnapshot(t *testing.T) {
	store := NewMemory()
	agent, _, err := store.Register(context.Background(), "agent", "host", "test")
	if err != nil {
		t.Fatal(err)
	}
	record := certificates.Record{Path: "/etc/ssl/a.pem", Subject: "CN=example", Issuer: "CN=test", SerialNumber: "1", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), SignatureAlgorithm: "SHA256-RSA", PublicKeyAlgorithm: "RSA", PublicKeyBits: 2048, FingerprintSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	_, inventory, err := store.Ingest(context.Background(), agent.ID, "host", "linux", "", []certificates.Record{record}, nil, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 1 {
		t.Fatal("certificate inventory was not stored")
	}
	_, _, err = store.Ingest(context.Background(), agent.ID, "host", "linux", "", []certificates.Record{record}, []string{inventory[0].ID}, policy.Default())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	count, err := store.EnqueueExpiringRenewals(context.Background(), now, policy.Default())
	if err != nil || count != 1 {
		t.Fatalf("automatic jobs = %d, %v", count, err)
	}
	count, err = store.EnqueueExpiringRenewals(context.Background(), now.Add(time.Minute), policy.Default())
	if err != nil || count != 0 {
		t.Fatalf("duplicate automatic jobs = %d, %v", count, err)
	}
}
