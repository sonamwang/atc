package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"
)

func TestDevelopmentCAIssuesSANCertificate(t *testing.T) {
	ca, err := OpenDevelopmentCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored.example.test"}, DNSNames: []string{"api.example.test"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ca.Issue(context.Background(), CertificateRequest{CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(result.CertificatePEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "api.example.test" {
		t.Fatalf("unexpected SANs: %v", cert.DNSNames)
	}
	if err := cert.CheckSignatureFrom(ca.certificate); err != nil {
		t.Fatal(err)
	}
}
func TestDevelopmentCARejectsCSRWithoutSAN(t *testing.T) {
	ca, err := OpenDevelopmentCA(filepath.Join(t.TempDir(), "ca"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ca.Issue(context.Background(), CertificateRequest{CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})})
	if err == nil {
		t.Fatal("CSR without SAN must be rejected")
	}
}
