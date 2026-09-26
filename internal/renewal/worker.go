package renewal

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/adaptive-trust/atc/internal/deployment"
	"github.com/adaptive-trust/atc/internal/issuer"
	"github.com/adaptive-trust/atc/internal/keys"
	"github.com/adaptive-trust/atc/internal/services"
)

type KeyManager interface{ keys.KeyStore }
type Stager = deployment.Deployer
type TransitionRecorder interface {
	Record(context.Context, State) error
}
type Job struct {
	KeyID, CertificatePath          string
	KeyDeploymentPath, KeyAlgorithm string
	RotateKey                       bool
	Subject                         pkix.Name
	DNSNames                        []string
	Lifetime                        time.Duration
}
type Worker struct {
	keys     KeyManager
	issuer   issuer.CertificateIssuer
	deployer Stager
	service  services.Provider
	tls      services.TLSValidator
}

func (w *Worker) WithTLSValidator(value services.TLSValidator) *Worker { w.tls = value; return w }

func NewWorker(keys KeyManager, issuer issuer.CertificateIssuer, deployer Stager, service services.Provider) *Worker {
	return &Worker{keys: keys, issuer: issuer, deployer: deployer, service: service}
}

// Execute changes a live certificate only after the replacement is parsed,
// staged, and the configured local service validates its resulting
// configuration. A failed service validation triggers rollback before return.
func (w *Worker) Execute(ctx context.Context, job Job, recorder TransitionRecorder) error {
	state := RenewalPending
	move := func(next State) error {
		if err := Transition(state, next); err != nil {
			return err
		}
		if err := recorder.Record(ctx, next); err != nil {
			return err
		}
		state = next
		return nil
	}
	fail := func(next State) {
		if Transition(state, next) == nil {
			_ = recorder.Record(ctx, next)
			state = next
		}
	}
	if err := move(Issuing); err != nil {
		return err
	}
	keyID := job.KeyID
	var keyPEM []byte
	if job.RotateKey {
		reference, generateErr := w.keys.GenerateKey(ctx, keys.KeyRequest{Algorithm: job.KeyAlgorithm})
		if generateErr != nil {
			fail(RenewalFailed)
			return fmt.Errorf("generate replacement key: %w", generateErr)
		}
		keyID = reference.ID
		keyPEM, generateErr = w.keys.PrivateKeyPEMForLocalDeployment(ctx, keyID)
		if generateErr != nil {
			fail(RenewalFailed)
			return fmt.Errorf("prepare replacement key: %w", generateErr)
		}
	}
	csr, err := w.keys.CreateCSR(ctx, keyID, keys.CSRRequest{Subject: job.Subject, DNSNames: job.DNSNames})
	if err != nil {
		fail(RenewalFailed)
		return fmt.Errorf("create renewal CSR: %w", err)
	}
	issued, err := w.issuer.Issue(ctx, issuer.CertificateRequest{CSRPEM: csr, Lifetime: job.Lifetime})
	if err != nil {
		fail(RenewalFailed)
		return fmt.Errorf("issue renewal certificate: %w", err)
	}
	if err := validateIssuedCertificate(issued.CertificatePEM, csr, job.DNSNames); err != nil {
		fail(RenewalFailed)
		return err
	}
	deploymentPEM, err := fullCertificateChain(issued.CertificatePEM, issued.ChainPEM)
	if err != nil {
		fail(RenewalFailed)
		return err
	}
	if err := move(Issued); err != nil {
		return err
	}
	var staged deployment.Staged
	if job.RotateKey {
		if job.KeyDeploymentPath == "" {
			fail(DeploymentFailed)
			return errors.New("key deployment path is required for rotation")
		}
		staged, err = w.deployer.StagePair(job.CertificatePath, job.KeyDeploymentPath, deploymentPEM, keyPEM)
	} else {
		staged, err = w.deployer.Stage(job.CertificatePath, deploymentPEM)
	}
	if err != nil {
		fail(DeploymentFailed)
		return fmt.Errorf("stage certificate: %w", err)
	}
	if err := move(Staged); err != nil {
		_ = staged.Discard()
		return err
	}
	if err := staged.Activate(); err != nil {
		_ = staged.Discard()
		fail(DeploymentFailed)
		return err
	}
	if err := move(Validating); err != nil {
		return w.rollback(staged, recorder, state, err)
	}
	if err := w.service.Validate(ctx); err != nil {
		return w.rollback(staged, recorder, state, err)
	}
	if err := w.service.Reload(ctx); err != nil {
		return w.rollback(staged, recorder, state, err)
	}
	status, err := w.service.Status(ctx)
	if err != nil || status != services.StatusActive {
		if err == nil {
			err = errors.New("service is not active after reload")
		}
		return w.rollback(staged, recorder, state, err)
	}
	if w.tls == nil {
		return w.rollback(staged, recorder, state, errors.New("TLS validator is required before certificate activation"))
	}
	if err := w.tls.Validate(ctx); err != nil {
		return w.rollback(staged, recorder, state, err)
	}
	if err := move(Active); err != nil {
		return w.rollback(staged, recorder, state, err)
	}
	if err := staged.Commit(); err != nil {
		// The validated replacement is live and its terminal state is already
		// recorded. Do not roll it back merely because backup cleanup failed.
		return fmt.Errorf("clean up committed certificate replacement: %w", err)
	}
	return nil
}
func (w *Worker) rollback(staged deployment.Staged, recorder TransitionRecorder, current State, cause error) error {
	failure := ValidationFailed
	if current == Staged {
		failure = DeploymentFailed
	}
	if Transition(current, failure) == nil {
		_ = recorder.Record(context.Background(), failure)
		current = failure
	}
	if err := staged.Rollback(); err != nil {
		return fmt.Errorf("%w; rollback failed: %v", cause, err)
	}
	if err := w.service.Reload(context.Background()); err != nil {
		return fmt.Errorf("%w; certificate restored but rollback service reload failed: %v", cause, err)
	}
	if Transition(current, RolledBack) == nil {
		_ = recorder.Record(context.Background(), RolledBack)
	}
	return fmt.Errorf("renewal validation failed and was rolled back: %w", cause)
}
func validateIssuedCertificate(certificatePEM, csrPEM []byte, wantedSANs []string) error {
	block, _ := pem.Decode(certificatePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("issuer returned invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse issued certificate: %w", err)
	}
	if time.Now().After(cert.NotAfter) {
		return errors.New("issued certificate is expired")
	}
	if time.Now().Before(cert.NotBefore) {
		return errors.New("issued certificate is not yet valid")
	}
	if err := validateServerCertificateUsage(cert); err != nil {
		return err
	}
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil || (csrBlock.Type != "CERTIFICATE REQUEST" && csrBlock.Type != "NEW CERTIFICATE REQUEST") {
		return errors.New("agent generated invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse renewal CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("verify renewal CSR: %w", err)
	}
	certificatePublicKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal issued certificate public key: %w", err)
	}
	csrPublicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal renewal CSR public key: %w", err)
	}
	if !bytes.Equal(certificatePublicKey, csrPublicKey) {
		return errors.New("issued certificate public key does not match renewal CSR")
	}
	for _, want := range wantedSANs {
		found := false
		for _, got := range cert.DNSNames {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("issued certificate is missing requested SAN %q", want)
		}
	}
	return nil
}

func fullCertificateChain(certificatePEM, chainPEM []byte) ([]byte, error) {
	leaf, err := certificateBlocks(certificatePEM)
	if err != nil || len(leaf) != 1 {
		return nil, errors.New("issuer returned an invalid leaf certificate PEM")
	}
	if len(chainPEM) == 0 {
		return pem.EncodeToMemory(leaf[0]), nil
	}
	chain, err := certificateBlocks(chainPEM)
	if err != nil || len(chain) == 0 {
		return nil, errors.New("issuer returned an invalid certificate chain PEM")
	}
	if !bytes.Equal(leaf[0].Bytes, chain[0].Bytes) {
		return nil, errors.New("issuer certificate chain does not begin with the issued leaf")
	}
	certificates := make([]*x509.Certificate, 0, len(chain))
	for _, block := range chain {
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		certificates = append(certificates, certificate)
	}
	for index := 0; index+1 < len(certificates); index++ {
		if err := certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			return nil, fmt.Errorf("certificate chain link %d is invalid: %w", index, err)
		}
	}
	var out []byte
	for _, block := range chain {
		out = append(out, pem.EncodeToMemory(block)...)
	}
	return out, nil
}

func validateServerCertificateUsage(certificate *x509.Certificate) error {
	if len(certificate.ExtKeyUsage) > 0 {
		serverAuth := false
		for _, usage := range certificate.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny {
				serverAuth = true
				break
			}
		}
		if !serverAuth {
			return errors.New("issued certificate is not valid for TLS server authentication")
		}
	}
	if certificate.KeyUsage != 0 && certificate.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) == 0 {
		return errors.New("issued certificate has no TLS server key usage")
	}
	return nil
}

func certificateBlocks(value []byte) ([]*pem.Block, error) {
	blocks := []*pem.Block{}
	for rest := value; len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, errors.New("unexpected non-PEM certificate data")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("unexpected non-certificate PEM block")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, fmt.Errorf("parse certificate chain: %w", err)
		}
		blocks = append(blocks, block)
		rest = next
	}
	return blocks, nil
}
