package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adaptive-trust/atc/internal/storage"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestLoadAgentRejectsUnsafeTargetAndUnknownFields(t *testing.T) {
	unsafe := writeConfig(t, "key_directory: /var/lib/atc/keys\ndeployment_roots: [/srv/certs]\nrenewal_targets:\n  - certificate_id: cert_a\n    certificate_path: /etc/shadow\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: 127.0.0.1:443\n    tls_server_name: api.example.test\n")
	if _, err := LoadAgent(unsafe); err == nil {
		t.Fatal("unsafe path accepted")
	}
	unknown := writeConfig(t, "key_directory: /var/lib/atc/keys\ndeployment_roots: [/srv/certs]\nunknown: true\n")
	if _, err := LoadAgent(unknown); err == nil {
		t.Fatal("unknown configuration field accepted")
	}
}
func TestResolveRequiresExplicitCertificateMapping(t *testing.T) {
	root := t.TempDir()
	path := writeConfig(t, "key_directory: "+root+"/keys\ndeployment_roots: ["+root+"/certs]\nrenewal_targets:\n  - certificate_id: cert_a\n    certificate_path: "+root+"/certs/api.pem\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: 127.0.0.1:443\n    tls_server_name: api.example.test\n")
	config, err := LoadAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	target, err := config.Resolve(storage.RenewalCommand{Job: storage.RenewalJob{CertificateID: "cert_a"}})
	if err != nil {
		t.Fatal(err)
	}
	if target.CertificatePath != filepath.Join(root, "certs", "api.pem") {
		t.Fatal(target.CertificatePath)
	}
	if _, err := config.Resolve(storage.RenewalCommand{Job: storage.RenewalJob{CertificateID: "cert_other"}}); err == nil {
		t.Fatal("unmapped certificate accepted")
	}
}
