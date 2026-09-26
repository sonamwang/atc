package deployment

import (
	"context"
	"errors"
	"testing"
)

type fakeSecretClient struct {
	data    map[string][]byte
	deleted bool
}

func (f *fakeSecretClient) Read(context.Context) (map[string][]byte, error) {
	if f.data == nil {
		return nil, ErrSecretNotFound
	}
	return copySecretData(f.data), nil
}
func (f *fakeSecretClient) Apply(_ context.Context, data map[string][]byte) error {
	f.data = copySecretData(data)
	return nil
}
func (f *fakeSecretClient) Delete(context.Context) error { f.data, f.deleted = nil, true; return nil }

func TestKubernetesSecretCertificateDeploymentRollsBack(t *testing.T) {
	client := &fakeSecretClient{data: map[string][]byte{"tls.crt": []byte("old certificate"), "tls.key": []byte("existing key"), "other": []byte("preserved")}}
	deployer, err := NewKubernetesSecretDeployerWithClient(KubernetesSecretConfig{Namespace: "security", Name: "api-tls", CertificateKey: "tls.crt", PrivateKey: "tls.key"}, client)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := deployer.Stage("ignored-by-kubernetes", []byte("replacement certificate"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Activate(); err != nil || string(client.data["tls.crt"]) != "replacement certificate" || string(client.data["other"]) != "preserved" {
		t.Fatalf("activate data=%q err=%v", client.data, err)
	}
	if err := stage.Rollback(); err != nil || string(client.data["tls.crt"]) != "old certificate" {
		t.Fatalf("rollback data=%q err=%v", client.data, err)
	}
}

func TestKubernetesSecretNewRotationIsRemovedOnRollback(t *testing.T) {
	client := &fakeSecretClient{}
	deployer, err := NewKubernetesSecretDeployerWithClient(KubernetesSecretConfig{Namespace: "security", Name: "api-tls", CertificateKey: "tls.crt", PrivateKey: "tls.key"}, client)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := deployer.StagePair("", "", []byte("certificate"), []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := stage.Rollback(); err != nil || !client.deleted {
		t.Fatalf("new secret rollback err=%v deleted=%v", err, client.deleted)
	}
}

func TestKubernetesSecretRejectsUnsafeIdentifiers(t *testing.T) {
	_, err := NewKubernetesSecretDeployerWithClient(KubernetesSecretConfig{Namespace: "security", Name: "../bad", CertificateKey: "tls.crt", PrivateKey: "tls.key"}, &fakeSecretClient{})
	if err == nil || errors.Is(err, ErrSecretNotFound) {
		t.Fatal("unsafe secret name accepted")
	}
}
