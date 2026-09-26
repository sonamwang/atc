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

func TestLoadAgentSupportsApacheAndRejectsUnknownService(t *testing.T) {
	root := t.TempDir()
	apache := writeConfig(t, "key_directory: "+root+"/keys\ndeployment_roots: ["+root+"/certs]\nrenewal_targets:\n  - certificate_id: cert_a\n    certificate_path: "+root+"/certs/api.pem\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: 127.0.0.1:443\n    tls_server_name: api.example.test\n    service: apache\n")
	loaded, err := LoadAgent(apache)
	if err != nil || loaded.RenewalTargets[0].Service != "apache" {
		t.Fatalf("apache config = %#v, %v", loaded, err)
	}
	unsupported := writeConfig(t, "key_directory: "+root+"/keys\ndeployment_roots: ["+root+"/certs]\nrenewal_targets:\n  - certificate_id: cert_a\n    certificate_path: "+root+"/certs/api.pem\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: 127.0.0.1:443\n    tls_server_name: api.example.test\n    service: shell\n")
	if _, err := LoadAgent(unsupported); err == nil {
		t.Fatal("unknown service accepted")
	}
}

func TestLoadAgentRequiresExplicitCompleteACMEConfiguration(t *testing.T) {
	root := t.TempDir()
	configured := writeConfig(t, "key_directory: "+root+"/keys\ndeployment_roots: ["+root+"/certs]\nrenewal_targets:\n  - certificate_id: cert_a\n    certificate_path: "+root+"/certs/api.pem\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: 127.0.0.1:443\n    tls_server_name: api.example.test\n    issuer: acme_http01\n    acme:\n      directory_url: https://acme-staging-v02.api.letsencrypt.org/directory\n      email: security@example.test\n      account_key_file: "+root+"/keys/account.pem\n      webroot: "+root+"/www\n      terms_of_service_accepted: true\n")
	loaded, err := LoadAgent(configured)
	if err != nil || loaded.RenewalTargets[0].Issuer != "acme_http01" {
		t.Fatalf("ACME config = %#v, %v", loaded, err)
	}
	incomplete := writeConfig(t, "key_directory: "+root+"/keys\ndeployment_roots: ["+root+"/certs]\nrenewal_targets:\n  - certificate_id: cert_a\n    certificate_path: "+root+"/certs/api.pem\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: 127.0.0.1:443\n    tls_server_name: api.example.test\n    issuer: acme_http01\n")
	if _, err := LoadAgent(incomplete); err == nil {
		t.Fatal("incomplete ACME config accepted")
	}
}

func TestLoadAgentSupportsKubernetesSecretDeploymentWithoutFileRoots(t *testing.T) {
	root := t.TempDir()
	kubernetes := writeConfig(t, "key_directory: "+root+"/keys\nrenewal_targets:\n  - certificate_id: cert_a\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: api.security.svc:443\n    tls_server_name: api.example.test\n    deployment: kubernetes_secret\n    service: kubernetes\n    kubernetes:\n      namespace: security\n      secret_name: api-tls\n      certificate_key: tls.crt\n      private_key: tls.key\n      deployment: api\n")
	loaded, err := LoadAgent(kubernetes)
	if err != nil || loaded.RenewalTargets[0].Deployment != "kubernetes_secret" {
		t.Fatalf("Kubernetes config = %#v, %v", loaded, err)
	}
}

func TestLoadAgentRejectsHardwareRotationAndRequiresPluginPath(t *testing.T) {
	root := t.TempDir()
	unsafe := writeConfig(t, "key_directory: "+root+"/keys\nkey_store: hardware_plugin\ndeployment_roots: ["+root+"/certs]\nrenewal_targets: []\n")
	if _, err := LoadAgent(unsafe); err == nil {
		t.Fatal("hardware store without plugin path accepted")
	}
	rotation := writeConfig(t, "key_directory: "+root+"/keys\nkey_store: hardware_plugin\nhardware_signer_plugin: /usr/local/libexec/atc-hardware-signer\ndeployment_roots: ["+root+"/certs]\nrenewal_targets:\n  - certificate_id: cert_a\n    certificate_path: "+root+"/certs/api.pem\n    key_deployment_path: "+root+"/certs/api.key\n    rotate_key: true\n    common_name: api.example.test\n    dns_names: [api.example.test]\n    tls_address: 127.0.0.1:443\n    tls_server_name: api.example.test\n")
	if _, err := LoadAgent(rotation); err == nil {
		t.Fatal("hardware key rotation accepted")
	}
}
