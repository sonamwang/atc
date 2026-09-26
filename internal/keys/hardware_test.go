package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"testing"
)

type hardwareRunnerFunc func(context.Context, []byte) ([]byte, error)

func (f hardwareRunnerFunc) Run(ctx context.Context, input []byte) ([]byte, error) {
	return f(ctx, input)
}

func TestHardwareKeyStoreUsesCSRPluginWithoutPrivateKeyExport(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewHardwareKeyStoreWithRunner(hardwareRunnerFunc(func(_ context.Context, input []byte) ([]byte, error) {
		var request pluginRequest
		if err := json.Unmarshal(input, &request); err != nil {
			return nil, err
		}
		switch request.Operation {
		case "generate":
			return json.Marshal(pluginResponse{KeyID: "pkcs11:slot-1/key-7", Algorithm: request.Algorithm})
		case "create_csr":
			der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: request.CommonName}, DNSNames: request.DNSNames}, private)
			if err != nil {
				return nil, err
			}
			return json.Marshal(pluginResponse{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
		default:
			return json.Marshal(pluginResponse{})
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	reference, err := store.GenerateKey(context.Background(), KeyRequest{Algorithm: "ECDSA_P256"})
	if err != nil || reference.ID != "pkcs11:slot-1/key-7" {
		t.Fatalf("key reference=%#v err=%v", reference, err)
	}
	csr, err := store.CreateCSR(context.Background(), reference.ID, CSRRequest{Subject: pkix.Name{CommonName: "api.example.test"}, DNSNames: []string{"api.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCSR(string(csr)); err != nil {
		t.Fatalf("returned CSR invalid: %v", err)
	}
	if _, err := store.PrivateKeyPEMForLocalDeployment(context.Background(), reference.ID); err == nil {
		t.Fatal("hardware private key was exportable")
	}
}

func TestHardwareKeyStoreRejectsMalformedPluginResponse(t *testing.T) {
	store, err := NewHardwareKeyStoreWithRunner(hardwareRunnerFunc(func(context.Context, []byte) ([]byte, error) { return []byte("not json"), nil }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GenerateKey(context.Background(), KeyRequest{}); err == nil {
		t.Fatal("malformed hardware response accepted")
	}
}
