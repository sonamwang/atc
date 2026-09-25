package services

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type call struct {
	name string
	args []string
}
type fakeRunner struct {
	calls []call
	out   []byte
	err   error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, append([]string{}, args...)})
	return f.out, f.err
}
func TestNginxProviderUsesFixedArgumentVectors(t *testing.T) {
	r := &fakeRunner{out: []byte("active\n")}
	p := NewNginxProviderWithRunner(r)
	if err := p.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := p.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status != StatusActive {
		t.Fatal(status)
	}
	want := []call{{"nginx", []string{"-t"}}, {"systemctl", []string{"reload", "nginx"}}, {"systemctl", []string{"is-active", "nginx"}}}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls=%#v", r.calls)
	}
}
func TestNginxProviderDoesNotMaskFailures(t *testing.T) {
	p := NewNginxProviderWithRunner(&fakeRunner{err: errors.New("failure")})
	if err := p.Validate(context.Background()); err == nil {
		t.Fatal("validate failure was accepted")
	}
}
