package services

import (
	"context"
	"reflect"
	"testing"
)

func TestApacheProviderUsesFixedArgumentVectors(t *testing.T) {
	r := &fakeRunner{out: []byte("active\n")}
	p := NewApacheProviderWithRunner(r)
	if err := p.Validate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := p.Status(context.Background())
	if err != nil || status != StatusActive {
		t.Fatalf("status=%s err=%v", status, err)
	}
	want := []call{{"apachectl", []string{"-t"}}, {"systemctl", []string{"reload", "apache2"}}, {"systemctl", []string{"is-active", "apache2"}}}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls=%#v", r.calls)
	}
}

func TestNewProviderRejectsUnknownService(t *testing.T) {
	if _, err := NewProvider("untrusted-command"); err == nil {
		t.Fatal("unknown service accepted")
	}
}
