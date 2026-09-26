package services

import (
	"context"
	"errors"
)

// ApacheProvider validates configuration before reload and confirms the
// service returned to an active state. It uses fixed process argument vectors
// and never evaluates configuration values through a shell.
type ApacheProvider struct {
	runner                           Runner
	apachectlBinary, systemctlBinary string
}

func NewApacheProvider() *ApacheProvider {
	return &ApacheProvider{runner: execRunner{}, apachectlBinary: "apachectl", systemctlBinary: "systemctl"}
}

func NewApacheProviderWithRunner(r Runner) *ApacheProvider {
	return &ApacheProvider{runner: r, apachectlBinary: "apachectl", systemctlBinary: "systemctl"}
}

func (p *ApacheProvider) Validate(ctx context.Context) error {
	if _, err := p.runner.Run(ctx, p.apachectlBinary, "-t"); err != nil {
		return errors.New("apache configuration validation failed")
	}
	return nil
}

func (p *ApacheProvider) Reload(ctx context.Context) error {
	if _, err := p.runner.Run(ctx, p.systemctlBinary, "reload", "apache2"); err != nil {
		return errors.New("apache reload failed")
	}
	return nil
}

func (p *ApacheProvider) Status(ctx context.Context) (Status, error) {
	out, err := p.runner.Run(ctx, p.systemctlBinary, "is-active", "apache2")
	if err != nil {
		return StatusInactive, err
	}
	if stringTrim(out) == "active" {
		return StatusActive, nil
	}
	return StatusInactive, nil
}
