package certificates

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Record contains public certificate metadata only. It is safe to send as inventory.
type Record struct {
	Path               string    `json:"path"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits"`
	SANs               []string  `json:"sans"`
	KeyUsages          []string  `json:"key_usage"`
	ExtendedKeyUsages  []string  `json:"extended_key_usage"`
	BasicConstraints   string    `json:"basic_constraints"`
	ChainLength        int       `json:"chain_length"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	SelfSigned         bool      `json:"self_signed"`
	DiscoveredAt       time.Time `json:"discovered_at"`
}

// ValidateRecord rejects malformed or oversized public inventory data before it
// reaches storage. It validates shape, not the truthfulness of agent claims.
func ValidateRecord(record Record) error {
	if record.Path == "" || len(record.Path) > 4096 || !filepath.IsAbs(record.Path) || filepath.Clean(record.Path) != record.Path || strings.IndexByte(record.Path, 0) >= 0 {
		return errors.New("certificate path must be a clean absolute path")
	}
	if err := limitedRequired("subject", record.Subject, 4096); err != nil {
		return err
	}
	if err := limitedRequired("issuer", record.Issuer, 4096); err != nil {
		return err
	}
	if err := limitedRequired("serial number", record.SerialNumber, 1024); err != nil {
		return err
	}
	if record.NotBefore.IsZero() || record.NotAfter.IsZero() || !record.NotAfter.After(record.NotBefore) {
		return errors.New("certificate validity period is invalid")
	}
	if err := limitedRequired("signature algorithm", record.SignatureAlgorithm, 128); err != nil {
		return err
	}
	if err := limitedRequired("public key algorithm", record.PublicKeyAlgorithm, 128); err != nil {
		return err
	}
	if record.PublicKeyBits < 0 || record.PublicKeyBits > 32768 {
		return errors.New("public key size is invalid")
	}
	if len(record.FingerprintSHA256) != sha256.Size*2 {
		return errors.New("certificate fingerprint must be a SHA-256 hex digest")
	}
	if _, err := hex.DecodeString(record.FingerprintSHA256); err != nil {
		return errors.New("certificate fingerprint must be a SHA-256 hex digest")
	}
	if len(record.SANs) > 100 {
		return errors.New("certificate has too many SANs")
	}
	seen := make(map[string]struct{}, len(record.SANs))
	for _, san := range record.SANs {
		if san == "" || len(san) > 2048 || strings.IndexByte(san, 0) >= 0 {
			return errors.New("certificate SAN is invalid")
		}
		if _, duplicate := seen[san]; duplicate {
			return errors.New("certificate SAN is duplicated")
		}
		seen[san] = struct{}{}
	}
	if err := validateUsageList("key usage", record.KeyUsages); err != nil {
		return err
	}
	if err := validateUsageList("extended key usage", record.ExtendedKeyUsages); err != nil {
		return err
	}
	if len(record.BasicConstraints) > 256 || strings.IndexByte(record.BasicConstraints, 0) >= 0 {
		return errors.New("certificate basic constraints are invalid")
	}
	if record.ChainLength < 0 || record.ChainLength > 100 {
		return errors.New("certificate chain length is invalid")
	}
	return nil
}

func validateUsageList(name string, usages []string) error {
	if len(usages) > 32 {
		return fmt.Errorf("certificate has too many %s values", name)
	}
	seen := make(map[string]struct{}, len(usages))
	for _, usage := range usages {
		if usage == "" || len(usage) > 128 || strings.IndexByte(usage, 0) >= 0 {
			return fmt.Errorf("certificate %s is invalid", name)
		}
		if _, duplicate := seen[usage]; duplicate {
			return fmt.Errorf("certificate %s is duplicated", name)
		}
		seen[usage] = struct{}{}
	}
	return nil
}

func limitedRequired(name, value string, max int) error {
	if value == "" || len(value) > max || strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("certificate %s is invalid", name)
	}
	return nil
}

func ParseFile(path string) ([]Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	var out []Record
	for rest := b; len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = next
		if block.Type != "CERTIFICATE" {
			continue
		}
		record, err := fromDER(path, block.Bytes)
		if err != nil {
			return out, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, record)
	}
	if len(out) > 0 {
		// A PEM deployment file normally contains a leaf followed by its
		// intermediates. The managed certificate is the first leaf; the rest
		// are represented as its observed chain rather than duplicate paths.
		out[0].ChainLength = len(out)
		return []Record{out[0]}, nil
	}
	// Permit a single DER certificate, but never interpret arbitrary key material as DER.
	if strings.Contains(string(b), "-----BEGIN") {
		return nil, errors.New("no certificate PEM block")
	}
	record, err := fromDER(path, b)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}
	return []Record{record}, nil
}

func fromDER(path string, der []byte) (Record, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return Record{}, err
	}
	h := sha256.Sum256(der)
	sans := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, u := range c.URIs {
		sans = append(sans, u.String())
	}
	return Record{Path: path, Subject: c.Subject.String(), Issuer: c.Issuer.String(), SerialNumber: c.SerialNumber.String(), NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), SignatureAlgorithm: c.SignatureAlgorithm.String(), PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(), PublicKeyBits: publicKeyBits(c), SANs: sans, KeyUsages: keyUsageNames(c.KeyUsage), ExtendedKeyUsages: extendedKeyUsageNames(c.ExtKeyUsage), BasicConstraints: basicConstraints(c), ChainLength: 1, FingerprintSHA256: hex.EncodeToString(h[:]), SelfSigned: c.CheckSignatureFrom(c) == nil, DiscoveredAt: time.Now().UTC()}, nil
}

func keyUsageNames(usages x509.KeyUsage) []string {
	known := []struct {
		value x509.KeyUsage
		name  string
	}{
		{x509.KeyUsageDigitalSignature, "digital_signature"},
		{x509.KeyUsageContentCommitment, "content_commitment"},
		{x509.KeyUsageKeyEncipherment, "key_encipherment"},
		{x509.KeyUsageDataEncipherment, "data_encipherment"},
		{x509.KeyUsageKeyAgreement, "key_agreement"},
		{x509.KeyUsageCertSign, "cert_sign"},
		{x509.KeyUsageCRLSign, "crl_sign"},
		{x509.KeyUsageEncipherOnly, "encipher_only"},
		{x509.KeyUsageDecipherOnly, "decipher_only"},
	}
	values := make([]string, 0, len(known))
	for _, usage := range known {
		if usages&usage.value != 0 {
			values = append(values, usage.name)
		}
	}
	return values
}

func extendedKeyUsageNames(usages []x509.ExtKeyUsage) []string {
	known := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:             "any",
		x509.ExtKeyUsageServerAuth:      "server_auth",
		x509.ExtKeyUsageClientAuth:      "client_auth",
		x509.ExtKeyUsageCodeSigning:     "code_signing",
		x509.ExtKeyUsageEmailProtection: "email_protection",
		x509.ExtKeyUsageTimeStamping:    "time_stamping",
		x509.ExtKeyUsageOCSPSigning:     "ocsp_signing",
	}
	values := make([]string, 0, len(usages))
	for _, usage := range usages {
		if name, ok := known[usage]; ok {
			values = append(values, name)
			continue
		}
		values = append(values, fmt.Sprintf("unknown_%d", usage))
	}
	return values
}

func basicConstraints(certificate *x509.Certificate) string {
	if !certificate.IsCA {
		return "CA:FALSE"
	}
	if certificate.MaxPathLenZero {
		return "CA:TRUE,path_len=0"
	}
	if certificate.MaxPathLen > 0 {
		return fmt.Sprintf("CA:TRUE,path_len=%d", certificate.MaxPathLen)
	}
	return "CA:TRUE"
}

func publicKeyBits(c *x509.Certificate) int {
	switch k := c.PublicKey.(type) {
	case interface{ Size() int }:
		return k.Size() * 8
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	}
	return 0
}
