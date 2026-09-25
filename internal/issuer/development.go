// Package issuer contains certificate-issuer implementations. DevelopmentCA is
// intentionally limited to local development and integration testing.
package issuer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const maxDevelopmentLifetime = 7 * 24 * time.Hour

type CertificateRequest struct {
	CSRPEM   []byte
	Lifetime time.Duration
}
type CertificateResult struct {
	CertificatePEM, ChainPEM []byte
	NotAfter                 time.Time
}

// ChainPEM, when present, is a full chain: the issued leaf certificate first,
// followed by its issuer certificates. It contains certificate PEM blocks only.
type CertificateIssuer interface {
	Issue(context.Context, CertificateRequest) (CertificateResult, error)
}
type DevelopmentCA struct {
	certificate *x509.Certificate
	privateKey  crypto.Signer
}

func OpenDevelopmentCA(directory string) (*DevelopmentCA, error) {
	if directory == "" {
		return nil, errors.New("development CA directory is required")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(directory, "root-ca.pem")
	keyPath := filepath.Join(directory, "root-ca-key.pem")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return decodeCA(certPEM, keyPEM)
	}
	if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return nil, errors.New("development CA material is incomplete")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ATC Development Root CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	derKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &DevelopmentCA{certificate: certificate, privateKey: key}, nil
}
func decodeCA(certPEM, keyPEM []byte) (*DevelopmentCA, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid development CA PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, errors.New("development CA certificate is not a CA")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("development CA key cannot sign")
	}
	return &DevelopmentCA{certificate: cert, privateKey: signer}, nil
}
func (ca *DevelopmentCA) Issue(ctx context.Context, request CertificateRequest) (CertificateResult, error) {
	if err := ctx.Err(); err != nil {
		return CertificateResult{}, err
	}
	block, _ := pem.Decode(request.CSRPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return CertificateResult{}, errors.New("request must contain a PEM certificate signing request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return CertificateResult{}, fmt.Errorf("verify CSR signature: %w", err)
	}
	lifetime := request.Lifetime
	if lifetime == 0 {
		lifetime = 24 * time.Hour
	}
	if lifetime < time.Minute || lifetime > maxDevelopmentLifetime {
		return CertificateResult{}, fmt.Errorf("development certificate lifetime must be between 1 minute and %s", maxDevelopmentLifetime)
	}
	if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 && len(csr.URIs) == 0 {
		return CertificateResult{}, errors.New("CSR requires at least one SAN")
	}
	if err := ctx.Err(); err != nil {
		return CertificateResult{}, err
	}
	serial, err := serialNumber()
	if err != nil {
		return CertificateResult{}, err
	}
	now := time.Now().UTC()
	keyUsage := x509.KeyUsageDigitalSignature
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: csr.Subject, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(lifetime), KeyUsage: keyUsage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses, URIs: csr.URIs, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.certificate, csr.PublicKey, ca.privateKey)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("issue certificate: %w", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chainPEM := append(append([]byte{}, certificatePEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certificate.Raw})...)
	return CertificateResult{CertificatePEM: certificatePEM, ChainPEM: chainPEM, NotAfter: tmpl.NotAfter}, nil
}
func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
