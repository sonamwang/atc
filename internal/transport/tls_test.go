package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSConfigurationsRequireCompleteCredentials(t *testing.T) {
	if _, err := NewHTTPClient("https://atc.example.test", time.Second, ClientTLSConfig{CertificateFile: "client.pem"}); err == nil {
		t.Fatal("incomplete client certificate accepted")
	}
	if _, err := LoadServerTLSConfig(ServerTLSConfig{RequireClientCert: true}); err == nil {
		t.Fatal("mutual TLS without a server certificate accepted")
	}
}

func TestTLSConfigurationsUseTLS13AndVerifiedClientCertificates(t *testing.T) {
	directory := t.TempDir()
	certificateFile, keyFile := writeTestCertificate(t, directory)
	server, err := LoadServerTLSConfig(ServerTLSConfig{CertificateFile: certificateFile, KeyFile: keyFile, ClientCAFile: certificateFile, RequireClientCert: true})
	if err != nil {
		t.Fatal(err)
	}
	if server.MinVersion != tls.VersionTLS13 || server.ClientAuth != tls.RequireAndVerifyClientCert || server.ClientCAs == nil {
		t.Fatalf("unexpected server TLS configuration: %#v", server)
	}
	client, err := NewHTTPClient("https://atc.example.test", time.Second, ClientTLSConfig{CAFile: certificateFile, CertificateFile: certificateFile, KeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if client.Transport == nil {
		t.Fatal("TLS client has no transport")
	}
}

func writeTestCertificate(t *testing.T, directory string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "atc.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	derKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificateFile := filepath.Join(directory, "certificate.pem")
	keyFile := filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey}), 0600); err != nil {
		t.Fatal(err)
	}
	return certificateFile, keyFile
}
