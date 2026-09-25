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
	CertificatePaths []string        `yaml:"certificate_paths"`
	DeploymentRoots  []string        `yaml:"deployment_roots"`
	KeyDirectory     string          `yaml:"key_directory"`
	RenewalTargets   []RenewalTarget `yaml:"renewal_targets"`
}
type RenewalTarget struct {
	CertificateID     string   `yaml:"certificate_id"`
	CertificatePath   string   `yaml:"certificate_path"`
	KeyID             string   `yaml:"key_id"`
	KeyDeploymentPath string   `yaml:"key_deployment_path"`
	KeyAlgorithm      string   `yaml:"key_algorithm"`
	CommonName        string   `yaml:"common_name"`
	DNSNames          []string `yaml:"dns_names"`
	RotateKey         bool     `yaml:"rotate_key"`
	TLSAddress        string   `yaml:"tls_address"`
	TLSServerName     string   `yaml:"tls_server_name"`
	TLSCAFile         string   `yaml:"tls_ca_file"`
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
	for i, root := range a.DeploymentRoots {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return err
		}
		a.DeploymentRoots[i] = filepath.Clean(absolute)
	}
	if len(a.DeploymentRoots) == 0 {
		return errors.New("at least one deployment_root is required")
	}
	seen := map[string]bool{}
	for i := range a.RenewalTargets {
		target := &a.RenewalTargets[i]
		if target.CertificateID == "" || target.CertificatePath == "" || target.CommonName == "" || len(target.DNSNames) == 0 || target.TLSAddress == "" || target.TLSServerName == "" {
			return errors.New("renewal target requires certificate_id, certificate_path, common_name, dns_names, tls_address, and tls_server_name")
		}
		if seen[target.CertificateID] {
			return fmt.Errorf("duplicate renewal target for %q", target.CertificateID)
		}
		seen[target.CertificateID] = true
		if target.KeyAlgorithm == "" {
			target.KeyAlgorithm = "ECDSA_P256"
		}
		if target.KeyAlgorithm != "ECDSA_P256" && target.KeyAlgorithm != "RSA_3072" {
			return fmt.Errorf("unsupported key algorithm %q", target.KeyAlgorithm)
		}
		if target.RotateKey && target.KeyDeploymentPath == "" {
			return fmt.Errorf("renewal target %q requires key_deployment_path when rotate_key is enabled", target.CertificateID)
		}
		if target.KeyDeploymentPath != "" {
			absolute, err := filepath.Abs(target.KeyDeploymentPath)
			if err != nil {
				return err
			}
			target.KeyDeploymentPath = filepath.Clean(absolute)
			if !insideRoots(target.KeyDeploymentPath, a.DeploymentRoots) {
				return fmt.Errorf("key deployment path for %q is outside deployment_roots", target.CertificateID)
			}
		}
		absolute, err := filepath.Abs(target.CertificatePath)
		if err != nil {
			return err
		}
		target.CertificatePath = filepath.Clean(absolute)
		if !insideRoots(target.CertificatePath, a.DeploymentRoots) {
			return fmt.Errorf("certificate path for %q is outside deployment_roots", target.CertificateID)
		}
		for _, san := range target.DNSNames {
			if strings.TrimSpace(san) == "" {
				return errors.New("dns_names cannot contain empty values")
			}
		}
	}
	return nil
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
