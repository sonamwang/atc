package deployment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

var ErrSecretNotFound = errors.New("Kubernetes Secret not found")

type KubernetesSecretConfig struct {
	Namespace, Name, CertificateKey, PrivateKey string
}

// KubernetesSecretClient deliberately exposes only the operations an ATC
// transaction needs. Authentication remains with local kubectl credentials or
// a pod service account; neither is accepted from the ATC control plane.
type KubernetesSecretClient interface {
	Read(context.Context) (map[string][]byte, error)
	Apply(context.Context, map[string][]byte) error
	Delete(context.Context) error
}

type KubernetesSecretDeployer struct {
	client KubernetesSecretClient
	config KubernetesSecretConfig
}

func NewKubernetesSecretDeployer(config KubernetesSecretConfig) (*KubernetesSecretDeployer, error) {
	return NewKubernetesSecretDeployerWithClient(config, &kubectlSecretClient{config: config})
}

func NewKubernetesSecretDeployerWithClient(config KubernetesSecretConfig, client KubernetesSecretClient) (*KubernetesSecretDeployer, error) {
	if !validKubernetesConfig(config) {
		return nil, errors.New("invalid Kubernetes Secret deployment configuration")
	}
	if client == nil {
		return nil, errors.New("Kubernetes Secret client is required")
	}
	return &KubernetesSecretDeployer{config: config, client: client}, nil
}

func (d *KubernetesSecretDeployer) Stage(_ string, certificate []byte) (Staged, error) {
	ctx, cancel := kubernetesContext()
	defer cancel()
	previous, err := d.client.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes Secret before certificate deployment: %w", err)
	}
	if len(previous[d.config.PrivateKey]) == 0 {
		return nil, errors.New("Kubernetes Secret has no existing private key for certificate-only renewal")
	}
	next := copySecretData(previous)
	next[d.config.CertificateKey] = append([]byte(nil), certificate...)
	return &stagedKubernetesSecret{client: d.client, previous: previous, next: next, existed: true}, nil
}

func (d *KubernetesSecretDeployer) StagePair(_ string, _ string, certificate, privateKey []byte) (Staged, error) {
	ctx, cancel := kubernetesContext()
	defer cancel()
	previous, err := d.client.Read(ctx)
	existed := true
	if errors.Is(err, ErrSecretNotFound) {
		previous, existed = map[string][]byte{}, false
	} else if err != nil {
		return nil, fmt.Errorf("read Kubernetes Secret before key rotation: %w", err)
	}
	next := copySecretData(previous)
	next[d.config.CertificateKey] = append([]byte(nil), certificate...)
	next[d.config.PrivateKey] = append([]byte(nil), privateKey...)
	return &stagedKubernetesSecret{client: d.client, previous: previous, next: next, existed: existed}, nil
}

type stagedKubernetesSecret struct {
	client         KubernetesSecretClient
	previous, next map[string][]byte
	existed        bool
	activated      bool
}

func (s *stagedKubernetesSecret) Activate() error {
	ctx, cancel := kubernetesContext()
	defer cancel()
	if err := s.client.Apply(ctx, copySecretData(s.next)); err != nil {
		return fmt.Errorf("apply replacement Kubernetes Secret: %w", err)
	}
	s.activated = true
	return nil
}
func (s *stagedKubernetesSecret) Rollback() error {
	if !s.activated {
		return nil
	}
	if s.existed {
		ctx, cancel := kubernetesContext()
		defer cancel()
		if err := s.client.Apply(ctx, copySecretData(s.previous)); err != nil {
			return fmt.Errorf("restore previous Kubernetes Secret: %w", err)
		}
		return nil
	}
	ctx, cancel := kubernetesContext()
	defer cancel()
	if err := s.client.Delete(ctx); err != nil {
		return fmt.Errorf("remove newly-created Kubernetes Secret: %w", err)
	}
	return nil
}

func kubernetesContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}
func (*stagedKubernetesSecret) Commit() error  { return nil }
func (*stagedKubernetesSecret) Discard() error { return nil }

func copySecretData(source map[string][]byte) map[string][]byte {
	copy := make(map[string][]byte, len(source))
	for key, value := range source {
		copy[key] = append([]byte(nil), value...)
	}
	return copy
}

type kubectlSecretClient struct{ config KubernetesSecretConfig }

func (c *kubectlSecretClient) Read(ctx context.Context) (map[string][]byte, error) {
	command := exec.CommandContext(ctx, "kubectl", "--namespace", c.config.Namespace, "get", "secret", c.config.Name, "-o", "json")
	output, err := command.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return nil, ErrSecretNotFound
		}
		return nil, errors.New("read Kubernetes Secret")
	}
	var document struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(output, &document); err != nil {
		return nil, errors.New("decode Kubernetes Secret")
	}
	data := make(map[string][]byte, len(document.Data))
	for key, encoded := range document.Data {
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("decode Kubernetes Secret data")
		}
		data[key] = value
	}
	return data, nil
}

func (c *kubectlSecretClient) Apply(ctx context.Context, data map[string][]byte) error {
	encoded := make(map[string]string, len(data))
	for key, value := range data {
		encoded[key] = base64.StdEncoding.EncodeToString(value)
	}
	type secret struct {
		APIVersion string            `json:"apiVersion"`
		Kind       string            `json:"kind"`
		Metadata   map[string]string `json:"metadata"`
		Type       string            `json:"type"`
		Data       map[string]string `json:"data"`
	}
	typeName := "Opaque"
	if c.config.CertificateKey == "tls.crt" && c.config.PrivateKey == "tls.key" {
		typeName = "kubernetes.io/tls"
	}
	document, err := json.Marshal(secret{APIVersion: "v1", Kind: "Secret", Metadata: map[string]string{"name": c.config.Name, "namespace": c.config.Namespace}, Type: typeName, Data: encoded})
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "kubectl", "--namespace", c.config.Namespace, "apply", "-f", "-")
	command.Stdin = bytes.NewReader(document)
	if err := command.Run(); err != nil {
		return errors.New("apply Kubernetes Secret")
	}
	return nil
}

func (c *kubectlSecretClient) Delete(ctx context.Context) error {
	command := exec.CommandContext(ctx, "kubectl", "--namespace", c.config.Namespace, "delete", "secret", c.config.Name, "--ignore-not-found=true")
	if err := command.Run(); err != nil {
		return errors.New("delete Kubernetes Secret")
	}
	return nil
}

func validKubernetesConfig(config KubernetesSecretConfig) bool {
	return validKubernetesName(config.Namespace) && validKubernetesName(config.Name) && validSecretDataKey(config.CertificateKey) && validSecretDataKey(config.PrivateKey) && config.CertificateKey != config.PrivateKey
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
func validSecretDataKey(value string) bool {
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
