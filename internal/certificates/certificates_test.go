package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validRecord() Record {
	return Record{
		Path:               "/etc/ssl/example.pem",
		Subject:            "CN=example.test",
		Issuer:             "CN=test issuer",
		SerialNumber:       "01",
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		SignatureAlgorithm: "SHA256-RSA",
		PublicKeyAlgorithm: "RSA",
		PublicKeyBits:      2048,
		SANs:               []string{"example.test"},
		FingerprintSHA256:  strings.Repeat("a", 64),
	}
}

func TestValidateRecordAcceptsPublicCertificateMetadata(t *testing.T) {
	if err := ValidateRecord(validRecord()); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
}

func TestValidateRecordRejectsUnsafeValues(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Record)
	}{
		{"relative path", func(record *Record) { record.Path = "relative.pem" }},
		{"unclean path", func(record *Record) { record.Path = "/etc/ssl/../private.pem" }},
		{"invalid dates", func(record *Record) { record.NotAfter = record.NotBefore }},
		{"invalid fingerprint", func(record *Record) { record.FingerprintSHA256 = "nope" }},
		{"duplicate SAN", func(record *Record) { record.SANs = []string{"example.test", "example.test"} }},
		{"duplicate key usage", func(record *Record) { record.KeyUsages = []string{"digital_signature", "digital_signature"} }},
		{"invalid chain length", func(record *Record) { record.ChainLength = 101 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			record := validRecord()
			test.mutate(&record)
			if err := ValidateRecord(record); err == nil {
				t.Fatal("unsafe record was accepted")
			}
		})
	}
}

func TestParseFileCollectsPublicUsageAndChainDetails(t *testing.T) {
	der := testCertificateDER(t)
	path := filepath.Join(t.TempDir(), "fullchain.pem")
	content := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	records, err := ParseFile(path)
	if err != nil || len(records) != 1 {
		t.Fatalf("parse full chain = %#v, %v", records, err)
	}
	record := records[0]
	if record.ChainLength != 2 || record.BasicConstraints != "CA:FALSE" || !contains(record.KeyUsages, "digital_signature") || !contains(record.KeyUsages, "key_encipherment") || !contains(record.ExtendedKeyUsages, "server_auth") || record.DiscoveredAt.IsZero() {
		t.Fatalf("unexpected parsed metadata: %#v", record)
	}
}

func testCertificateDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              []string{"example.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
