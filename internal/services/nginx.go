package services

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

type Status string

const (
	StatusActive   Status = "ACTIVE"
	StatusInactive Status = "INACTIVE"
)

type Provider interface {
	Validate(context.Context) error
	Reload(context.Context) error
	Status(context.Context) (Status, error)
}
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// NginxProvider uses fixed argument vectors and never invokes a shell.
type NginxProvider struct {
	runner                       Runner
	nginxBinary, systemctlBinary string
}

func NewNginxProvider() *NginxProvider {
	return &NginxProvider{runner: execRunner{}, nginxBinary: "nginx", systemctlBinary: "systemctl"}
}
func NewNginxProviderWithRunner(r Runner) *NginxProvider {
	return &NginxProvider{runner: r, nginxBinary: "nginx", systemctlBinary: "systemctl"}
}
func (p *NginxProvider) Validate(ctx context.Context) error {
	_, err := p.runner.Run(ctx, p.nginxBinary, "-t")
	if err != nil {
		return errors.New("nginx configuration validation failed")
	}
	return nil
}
func (p *NginxProvider) Reload(ctx context.Context) error {
	_, err := p.runner.Run(ctx, p.systemctlBinary, "reload", "nginx")
	if err != nil {
		return errors.New("nginx reload failed")
	}
	return nil
}
func (p *NginxProvider) Status(ctx context.Context) (Status, error) {
	out, err := p.runner.Run(ctx, p.systemctlBinary, "is-active", "nginx")
	if err != nil {
		return StatusInactive, err
	}
	if stringTrim(out) == "active" {
		return StatusActive, nil
	}
	return StatusInactive, nil
}
func stringTrim(b []byte) string {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return string(b)
}

// NewProvider only accepts service identifiers from trusted local agent
// configuration. Callers cannot supply command paths or arbitrary arguments.
func NewProvider(service string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "", "nginx":
		return NewNginxProvider(), nil
	case "apache", "apache2":
		return NewApacheProvider(), nil
	default:
		return nil, errors.New("unsupported web service")
	}
}
