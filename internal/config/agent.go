// Package config loads trusted agent configuration. Inventory data must never
// be used as a deployment instruction.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/adaptive-trust/atc/internal/storage"
	"gopkg.in/yaml.v3"
)

type Agent struct {
	CertificatePaths     []string        `yaml:"certificate_paths"`
	DeploymentRoots      []string        `yaml:"deployment_roots"`
	KeyDirectory         string          `yaml:"key_directory"`
	KeyStore             string          `yaml:"key_store"`
	HardwareSignerPlugin string          `yaml:"hardware_signer_plugin"`
	RenewalTargets       []RenewalTarget `yaml:"renewal_targets"`
}
type RenewalTarget struct {
	CertificateID     string           `yaml:"certificate_id"`
	CertificatePath   string           `yaml:"certificate_path"`
	KeyID             string           `yaml:"key_id"`
	KeyDeploymentPath string           `yaml:"key_deployment_path"`
	KeyAlgorithm      string           `yaml:"key_algorithm"`
	CommonName        string           `yaml:"common_name"`
	DNSNames          []string         `yaml:"dns_names"`
	RotateKey         bool             `yaml:"rotate_key"`
	TLSAddress        string           `yaml:"tls_address"`
	TLSServerName     string           `yaml:"tls_server_name"`
	TLSCAFile         string           `yaml:"tls_ca_file"`
	Service           string           `yaml:"service"`
	Issuer            string           `yaml:"issuer"`
	ACME              ACMEHTTP01       `yaml:"acme"`
	Deployment        string           `yaml:"deployment"`
	Kubernetes        KubernetesSecret `yaml:"kubernetes"`
}

type KubernetesSecret struct {
	Namespace      string `yaml:"namespace"`
	SecretName     string `yaml:"secret_name"`
	CertificateKey string `yaml:"certificate_key"`
	PrivateKey     string `yaml:"private_key"`
	Deployment     string `yaml:"deployment"`
}

// ACMEHTTP01 is deliberately nested in trusted local agent configuration.
// Nothing received from the ATC server can select a CA or write a challenge.
type ACMEHTTP01 struct {
	DirectoryURL           string `yaml:"directory_url"`
	Email                  string `yaml:"email"`
	AccountKeyFile         string `yaml:"account_key_file"`
	Webroot                string `yaml:"webroot"`
	TermsOfServiceAccepted bool   `yaml:"terms_of_service_accepted"`
}

func LoadAgent(path string) (Agent, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Agent{}, fmt.Errorf("inspect agent config: %w", err)
	}
	if info.Size() > 1<<20 {
		return Agent{}, errors.New("agent config exceeds 1 MiB")
	}
	file, err := os.Open(path)
	if err != nil {
		return Agent{}, err
	}
	defer file.Close()
	decoder := yaml.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.KnownFields(true)
	var config Agent
	if err = decoder.Decode(&config); err != nil {
		return Agent{}, fmt.Errorf("decode agent config: %w", err)
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return Agent{}, errors.New("agent config must contain one YAML document")
	}
	if err = validate(&config); err != nil {
		return Agent{}, err
	}
	return config, nil
}
func (a Agent) Resolve(command storage.RenewalCommand) (RenewalTarget, error) {
	for _, target := range a.RenewalTargets {
		if target.CertificateID == command.Job.CertificateID {
			return target, nil
		}
	}
	return RenewalTarget{}, errors.New("no trusted renewal target is configured for certificate")
}

// RenewalCertificateIDs returns the public, stable certificate IDs for which
// this trusted local configuration permits renewal. It exposes no paths, keys,
// or other deployment instructions.
func (a Agent) RenewalCertificateIDs() []string {
	ids := make([]string, 0, len(a.RenewalTargets))
	for _, target := range a.RenewalTargets {
		ids = append(ids, target.CertificateID)
	}
	return ids
}
func validate(a *Agent) error {
	if a.KeyDirectory == "" {
		return errors.New("key_directory is required")
	}
	if a.KeyStore == "" {
		a.KeyStore = "file"
	}
	if a.KeyStore != "file" && a.KeyStore != "hardware_plugin" {
		return fmt.Errorf("unsupported key_store %q", a.KeyStore)
	}
	if a.KeyStore == "hardware_plugin" {
		if a.HardwareSignerPlugin == "" || !filepath.IsAbs(a.HardwareSignerPlugin) {
			return errors.New("hardware_plugin key_store requires an absolute hardware_signer_plugin path")
		}
		a.HardwareSignerPlugin = filepath.Clean(a.HardwareSignerPlugin)
	}
	for i, root := range a.DeploymentRoots {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		a.DeploymentRoots[i] = filepath.Clean(absolute)
	}
	seen := map[string]bool{}
	requiresFileRoots := false
	for i := range a.RenewalTargets {
		target := &a.RenewalTargets[i]
		if target.CertificateID == "" || target.CommonName == "" || len(target.DNSNames) == 0 || target.TLSAddress == "" || target.TLSServerName == "" {
			return errors.New("renewal target requires certificate_id, common_name, dns_names, tls_address, and tls_server_name")
		}
		if seen[target.CertificateID] {
			return fmt.Errorf("duplicate renewal target for %q", target.CertificateID)
		}
		seen[target.CertificateID] = true
		if target.KeyAlgorithm == "" {
			target.KeyAlgorithm = "ECDSA_P256"
		}
		if target.Deployment == "" {
			target.Deployment = "files"
		}
		if target.Deployment != "files" && target.Deployment != "kubernetes_secret" {
			return fmt.Errorf("unsupported deployment %q", target.Deployment)
		}
		if target.Service == "" {
			if target.Deployment == "kubernetes_secret" {
				target.Service = "kubernetes"
			} else {
				target.Service = "nginx"
			}
		}
		if target.Service != "nginx" && target.Service != "apache" && target.Service != "apache2" && target.Service != "kubernetes" {
			return fmt.Errorf("unsupported service %q", target.Service)
		}
		if target.Deployment == "kubernetes_secret" && target.Service != "kubernetes" {
			return errors.New("Kubernetes Secret deployment requires service: kubernetes")
		}
		if target.Issuer == "" {
			target.Issuer = "control_plane"
		}
		if target.Issuer != "control_plane" && target.Issuer != "acme_http01" {
			return fmt.Errorf("unsupported issuer %q", target.Issuer)
		}
		if target.Issuer == "acme_http01" {
			if target.ACME.DirectoryURL == "" || target.ACME.Email == "" || target.ACME.AccountKeyFile == "" || target.ACME.Webroot == "" || !target.ACME.TermsOfServiceAccepted {
				return fmt.Errorf("ACME target %q requires directory_url, email, account_key_file, webroot, and terms_of_service_accepted: true", target.CertificateID)
			}
			for _, entry := range []struct {
				name string
				path *string
			}{{"ACME account_key_file", &target.ACME.AccountKeyFile}, {"ACME webroot", &target.ACME.Webroot}} {
				absolute, err := filepath.Abs(*entry.path)
				if err != nil {
					return err
				}
				*entry.path = filepath.Clean(absolute)
			}
		}
		if target.KeyAlgorithm != "ECDSA_P256" && target.KeyAlgorithm != "RSA_3072" {
			return fmt.Errorf("unsupported key algorithm %q", target.KeyAlgorithm)
		}
		if target.Deployment == "files" && target.CertificatePath == "" {
			return fmt.Errorf("file deployment target %q requires certificate_path", target.CertificateID)
		}
		if target.Deployment == "files" && target.RotateKey && target.KeyDeploymentPath == "" {
			return fmt.Errorf("renewal target %q requires key_deployment_path when rotate_key is enabled", target.CertificateID)
		}
		if a.KeyStore == "hardware_plugin" && target.RotateKey {
			return fmt.Errorf("hardware-backed target %q cannot rotate into a file or Kubernetes Secret private key", target.CertificateID)
		}
		if target.Deployment == "files" && target.KeyDeploymentPath != "" {
			absolute, err := filepath.Abs(target.KeyDeploymentPath)
			if err != nil {
				return err
			}
			target.KeyDeploymentPath = filepath.Clean(absolute)
			if !insideRoots(target.KeyDeploymentPath, a.DeploymentRoots) {
				return fmt.Errorf("key deployment path for %q is outside deployment_roots", target.CertificateID)
			}
		}
		if target.Deployment == "files" {
			requiresFileRoots = true
			absolute, err := filepath.Abs(target.CertificatePath)
			if err != nil {
				return err
			}
			target.CertificatePath = filepath.Clean(absolute)
			if !insideRoots(target.CertificatePath, a.DeploymentRoots) {
				return fmt.Errorf("certificate path for %q is outside deployment_roots", target.CertificateID)
			}
		} else if !validKubernetes(target.Kubernetes) {
			return fmt.Errorf("Kubernetes target %q requires valid namespace, secret_name, certificate_key, private_key, and deployment", target.CertificateID)
		}
		for _, san := range target.DNSNames {
			if strings.TrimSpace(san) == "" {
				return errors.New("dns_names cannot contain empty values")
			}
		}
	}
	if requiresFileRoots && len(a.DeploymentRoots) == 0 {
		return errors.New("at least one deployment_root is required for file deployments")
	}
	return nil
}

func validKubernetes(value KubernetesSecret) bool {
	return validKubernetesName(value.Namespace) && validKubernetesName(value.SecretName) && validKubernetesName(value.Deployment) && validKubernetesDataKey(value.CertificateKey) && validKubernetesDataKey(value.PrivateKey) && value.CertificateKey != value.PrivateKey
}
func validKubernetesName(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-') {
			return false
		}
	}
	return true
}
func validKubernetesDataKey(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.Contains(value, "..") || strings.HasPrefix(value, "/") {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}
func insideRoots(path string, roots []string) bool {
	for _, root := range roots {
		relative, err := filepath.Rel(root, path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return true
		}
	}
	return false
}
