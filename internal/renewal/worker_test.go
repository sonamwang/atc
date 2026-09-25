package renewal

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adaptive-trust/atc/internal/deployment"
	"github.com/adaptive-trust/atc/internal/issuer"
	"github.com/adaptive-trust/atc/internal/keys"
	"github.com/adaptive-trust/atc/internal/services"
)

type recorder struct{ states []State }

func (r *recorder) Record(_ context.Context, state State) error {
	r.states = append(r.states, state)
	return nil
}

type failingRecorder struct {
	recorder
	fail State
}

func (r *failingRecorder) Record(ctx context.Context, state State) error {
	if state == r.fail {
		return errors.New("control-plane state update failed")
	}
	return r.recorder.Record(ctx, state)
}

type service struct {
	validateErr, reloadErr error
	reloads                int
}
type tlsValidator struct{ err error }

func (v tlsValidator) Validate(context.Context) error { return v.err }

func (s *service) Validate(context.Context) error { return s.validateErr }
func (s *service) Reload(context.Context) error   { s.reloads++; return s.reloadErr }
func (s *service) Status(context.Context) (services.Status, error) {
	if s.validateErr != nil {
		return services.StatusInactive, errors.New("not active")
	}
	return services.StatusActive, nil
}
func workerFixture(t *testing.T, fail bool) (*Worker, Job, *recorder, string) {
	t.Helper()
	root := t.TempDir()
	target := filepath.Join(root, "server.pem")
	if err := os.WriteFile(target, []byte("old certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	store, err := keys.NewFileKeyStore(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := store.GenerateKey(context.Background(), keys.KeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := issuer.OpenDevelopmentCA(filepath.Join(root, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	deployer, err := deployment.NewFileDeployer([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	svc := &service{}
	if fail {
		svc.validateErr = errors.New("nginx invalid")
	}
	return NewWorker(store, ca, deployer, svc).WithTLSValidator(tlsValidator{}), Job{KeyID: key.ID, CertificatePath: target, Subject: pkix.Name{CommonName: "api.example.test"}, DNSNames: []string{"api.example.test"}, Lifetime: time.Hour}, &recorder{}, target
}
func TestWorkerActivatesValidatedCertificate(t *testing.T) {
	worker, job, record, target := workerFixture(t, false)
	if err := worker.Execute(context.Background(), job, record); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == "old certificate" {
		t.Fatal("certificate was not replaced")
	}
	blocks := 0
	for rest := b; len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		blocks++
		rest = next
	}
	if blocks != 2 {
		t.Fatalf("deployed certificate chain blocks = %d, want 2", blocks)
	}
	if got := record.states[len(record.states)-1]; got != Active {
		t.Fatalf("final state=%s", got)
	}
}

func TestFullCertificateChainRejectsUnexpectedPEM(t *testing.T) {
	if _, err := fullCertificateChain([]byte("-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"), nil); err == nil {
		t.Fatal("non-certificate leaf was accepted")
	}
}

func TestValidateServerCertificateUsage(t *testing.T) {
	if err := validateServerCertificateUsage(&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("client-only certificate accepted")
	}
	if err := validateServerCertificateUsage(&x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}); err != nil {
		t.Fatalf("server certificate rejected: %v", err)
	}
}
func TestWorkerRollsBackOnValidationFailure(t *testing.T) {
	worker, job, record, target := workerFixture(t, true)
	if err := worker.Execute(context.Background(), job, record); err == nil {
		t.Fatal("validation failure succeeded")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old certificate" {
		t.Fatalf("certificate was not restored: %q", b)
	}
	if got := record.states[len(record.states)-1]; got != RolledBack {
		t.Fatalf("final state=%s", got)
	}
}
func TestRollbackDoesNotClaimSuccessWhenServiceReloadFails(t *testing.T) {
	worker, job, record, target := workerFixture(t, true)
	worker.service.(*service).reloadErr = errors.New("reload failed")
	if err := worker.Execute(context.Background(), job, record); err == nil {
		t.Fatal("rollback reload failure succeeded")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old certificate" {
		t.Fatalf("certificate was not restored: %q", b)
	}
	for _, state := range record.states {
		if state == RolledBack {
			t.Fatal("worker claimed rollback despite reload failure")
		}
	}
}
func TestWorkerRollsBackWhenValidatingStateCannotBeRecorded(t *testing.T) {
	worker, job, _, target := workerFixture(t, false)
	record := &failingRecorder{fail: Validating}
	if err := worker.Execute(context.Background(), job, record); err == nil {
		t.Fatal("state-recording failure succeeded")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old certificate" {
		t.Fatalf("certificate was not restored: %q", b)
	}
	if got := record.states[len(record.states)-1]; got != RolledBack {
		t.Fatalf("final state=%s", got)
	}
}
func TestWorkerRollsBackWhenActiveStateCannotBeRecorded(t *testing.T) {
	worker, job, _, target := workerFixture(t, false)
	record := &failingRecorder{fail: Active}
	if err := worker.Execute(context.Background(), job, record); err == nil {
		t.Fatal("state-recording failure succeeded")
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old certificate" {
		t.Fatalf("certificate was not restored: %q", b)
	}
	if got := record.states[len(record.states)-1]; got != RolledBack {
		t.Fatalf("final state=%s", got)
	}
}
func TestWorkerRotatesKeyWithCertificate(t *testing.T) {
	root := t.TempDir()
	certificatePath := filepath.Join(root, "server.pem")
	keyPath := filepath.Join(root, "server.key")
	if err := os.WriteFile(certificatePath, []byte("old certificate"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("old key"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := keys.NewFileKeyStore(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := issuer.OpenDevelopmentCA(filepath.Join(root, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	deployer, err := deployment.NewFileDeployer([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	worker := NewWorker(store, ca, deployer, &service{}).WithTLSValidator(tlsValidator{})
	record := &recorder{}
	job := Job{RotateKey: true, KeyAlgorithm: "ECDSA_P256", CertificatePath: certificatePath, KeyDeploymentPath: keyPath, Subject: pkix.Name{CommonName: "api.example.test"}, DNSNames: []string{"api.example.test"}, Lifetime: time.Hour}
	if err := worker.Execute(context.Background(), job, record); err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	private, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(private.(crypto.Signer).Public())
	if err != nil {
		t.Fatal(err)
	}
	certificateDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(publicDER) != string(certificateDER) {
		t.Fatal("rotated key does not match certificate")
	}
}

func TestIssuedCertificateMustMatchRenewalCSRKey(t *testing.T) {
	root := t.TempDir()
	store, err := keys.NewFileKeyStore(filepath.Join(root, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.GenerateKey(context.Background(), keys.KeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.GenerateKey(context.Background(), keys.KeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	firstCSR, err := store.CreateCSR(context.Background(), first.ID, keys.CSRRequest{Subject: pkix.Name{CommonName: "api.example.test"}, DNSNames: []string{"api.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	secondCSR, err := store.CreateCSR(context.Background(), second.ID, keys.CSRRequest{Subject: pkix.Name{CommonName: "api.example.test"}, DNSNames: []string{"api.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := issuer.OpenDevelopmentCA(filepath.Join(root, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.Issue(context.Background(), issuer.CertificateRequest{CSRPEM: secondCSR, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIssuedCertificate(issued.CertificatePEM, firstCSR, []string{"api.example.test"}); err == nil {
		t.Fatal("issued certificate for another CSR key was accepted")
	}
}
