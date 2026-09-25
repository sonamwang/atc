package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyStoreGeneratesSignsAndDeletes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.GenerateKey(context.Background(), KeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, ref.ID+".pk8"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key file mode = %o", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("directory mode = %o", dirInfo.Mode().Perm())
	}
	message := []byte("ATC test")
	sig, err := store.Sign(context.Background(), ref.ID, message)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ref.ID+".pk8"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("stored key is not PEM")
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := private.(*ecdsa.PrivateKey)
	sum := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(&key.PublicKey, sum[:], sig) {
		t.Fatal("signature did not verify")
	}
	if err := store.Delete(context.Background(), ref.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ref.ID+".pk8")); !os.IsNotExist(err) {
		t.Fatalf("key remains after delete: %v", err)
	}
}
func TestUnsupportedAlgorithm(t *testing.T) {
	store, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GenerateKey(context.Background(), KeyRequest{Algorithm: "CUSTOM"}); err == nil {
		t.Fatal("custom algorithm must be rejected")
	}
}
func TestKeyIDCannotTraversePath(t *testing.T) {
	store, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Sign(context.Background(), "key_../../etc/passwd", []byte("x")); err == nil {
		t.Fatal("path traversal key ID must be rejected")
	}
}
func TestCreateCSRUsesAgentLocalKey(t *testing.T) {
	store, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := store.GenerateKey(context.Background(), KeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := store.CreateCSR(context.Background(), ref.ID, CSRRequest{Subject: pkix.Name{CommonName: "api.example.test"}, DNSNames: []string{"api.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != "api.example.test" {
		t.Fatalf("unexpected SANs: %v", csr.DNSNames)
	}
}
func TestPrivateKeyMaterialStaysLocalAndIsCopied(t *testing.T) {
	store, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.GenerateKey(context.Background(), KeyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.PrivateKeyPEMForLocalDeployment(context.Background(), reference.ID)
	if err != nil {
		t.Fatal(err)
	}
	first[0] = 'x'
	second, err := store.PrivateKeyPEMForLocalDeployment(context.Background(), reference.ID)
	if err != nil {
		t.Fatal(err)
	}
	if second[0] == 'x' {
		t.Fatal("returned key aliases on-disk material")
	}
}
