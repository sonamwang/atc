package services

import (
	"context"
	"errors"
	"fmt"
)

// KubernetesProvider performs a bounded rollout of a trusted, configured
// Deployment after a Secret is activated. It accepts no server-supplied names.
type KubernetesProvider struct {
	runner              Runner
	namespace, workload string
}

func NewKubernetesProvider(namespace, deployment string) (*KubernetesProvider, error) {
	if !validKubernetesName(namespace) || !validKubernetesName(deployment) {
		return nil, errors.New("invalid Kubernetes namespace or deployment")
	}
	return &KubernetesProvider{runner: execRunner{}, namespace: namespace, workload: deployment}, nil
}

func NewKubernetesProviderWithRunner(namespace, deployment string, runner Runner) (*KubernetesProvider, error) {
	provider, err := NewKubernetesProvider(namespace, deployment)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		return nil, errors.New("Kubernetes command runner is required")
	}
	provider.runner = runner
	return provider, nil
}

func (p *KubernetesProvider) Validate(ctx context.Context) error {
	if _, err := p.runner.Run(ctx, "kubectl", "--namespace", p.namespace, "get", "deployment", p.workload, "-o", "name"); err != nil {
		return errors.New("Kubernetes deployment validation failed")
	}
	return nil
}
func (p *KubernetesProvider) Reload(ctx context.Context) error {
	if _, err := p.runner.Run(ctx, "kubectl", "--namespace", p.namespace, "rollout", "restart", "deployment/"+p.workload); err != nil {
		return errors.New("Kubernetes rollout restart failed")
	}
	return nil
}
func (p *KubernetesProvider) Status(ctx context.Context) (Status, error) {
	if _, err := p.runner.Run(ctx, "kubectl", "--namespace", p.namespace, "rollout", "status", "deployment/"+p.workload, "--timeout=90s"); err != nil {
		return StatusInactive, fmt.Errorf("Kubernetes rollout status failed: %w", err)
	}
	return StatusActive, nil
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
