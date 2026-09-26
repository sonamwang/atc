package services

import (
	"context"
	"reflect"
	"testing"
)

func TestKubernetesProviderUsesFixedKubectlCommands(t *testing.T) {
	runner := &fakeRunner{}
	provider, err := NewKubernetesProviderWithRunner("security", "api", runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := provider.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status, err := provider.Status(context.Background()); err != nil || status != StatusActive {
		t.Fatalf("status=%s err=%v", status, err)
	}
	want := []call{{"kubectl", []string{"--namespace", "security", "get", "deployment", "api", "-o", "name"}}, {"kubectl", []string{"--namespace", "security", "rollout", "restart", "deployment/api"}}, {"kubectl", []string{"--namespace", "security", "rollout", "status", "deployment/api", "--timeout=90s"}}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%#v", runner.calls)
	}
}
