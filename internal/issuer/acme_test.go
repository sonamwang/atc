package issuer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestACMEHTTP01ConfigRejectsUnsafeOrImplicitSettings(t *testing.T) {
	root := t.TempDir()
	base := ACMEHTTP01Config{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory", Email: "security@example.test", AccountKeyFile: filepath.Join(root, "account.pem"), Webroot: root, TermsOfServiceAccepted: true}
	if _, err := NewACMEHTTP01Issuer(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	base.TermsOfServiceAccepted = false
	if _, err := NewACMEHTTP01Issuer(base); err == nil {
		t.Fatal("implicit terms acceptance accepted")
	}
	base.TermsOfServiceAccepted = true
	base.DirectoryURL = "http://acme.example.test/directory"
	if _, err := NewACMEHTTP01Issuer(base); err == nil {
		t.Fatal("HTTP ACME directory accepted")
	}
}

func TestACMEAccountKeyAndChallengeFileArePrivateAndTemporary(t *testing.T) {
	root := t.TempDir()
	keyPath := filepath.Join(root, "state", "account.pem")
	if _, err := loadOrCreateACMEAccountKey(keyPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("account key mode = %v, err=%v", info.Mode().Perm(), err)
	}
	remove, err := writeHTTP01Challenge(root, "challenge_token-01", "key-authorization")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".well-known", "acme-challenge", "challenge_token-01")
	if data, err := os.ReadFile(path); err != nil || string(data) != "key-authorization" {
		t.Fatalf("challenge file = %q, err=%v", data, err)
	}
	remove()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("challenge was not removed: %v", err)
	}
}
