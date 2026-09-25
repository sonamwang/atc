// Package keys manages agent-local private keys. Key bytes never leave this package.
package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type KeyRequest struct{ Algorithm string }
type KeyReference struct{ ID, Algorithm string }
type CSRRequest struct {
	Subject  pkix.Name
	DNSNames []string
}
type KeyStore interface {
	GenerateKey(context.Context, KeyRequest) (KeyReference, error)
	CreateCSR(context.Context, string, CSRRequest) ([]byte, error)
	PrivateKeyPEMForLocalDeployment(context.Context, string) ([]byte, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	Delete(context.Context, string) error
}

// PrivateKeyPEMForLocalDeployment is restricted to the agent process. Callers
// must stage the bytes directly into a protected local service path and never
// transmit, log, or retain them beyond that operation.
func (s *FileKeyStore) PrivateKeyPEMForLocalDeployment(ctx context.Context, id string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, err := s.keyPath(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read local private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("stored private key is not a PKCS#8 PEM block")
	}
	return append([]byte{}, data...), nil
}

func (s *FileKeyStore) CreateCSR(ctx context.Context, id string, request CSRRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(request.DNSNames) == 0 {
		return nil, errors.New("CSR requires at least one DNS SAN")
	}
	private, err := s.load(id)
	if err != nil {
		return nil, err
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		return nil, errors.New("stored key cannot sign")
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: request.Subject, DNSNames: request.DNSNames}, signer)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

type FileKeyStore struct{ directory string }

func NewFileKeyStore(directory string) (*FileKeyStore, error) {
	if directory == "" {
		return nil, errors.New("key directory is required")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return nil, fmt.Errorf("protect key directory: %w", err)
	}
	return &FileKeyStore{directory: directory}, nil
}
func (s *FileKeyStore) GenerateKey(ctx context.Context, req KeyRequest) (KeyReference, error) {
	if err := ctx.Err(); err != nil {
		return KeyReference{}, err
	}
	algorithm := req.Algorithm
	if algorithm == "" {
		algorithm = "ECDSA_P256"
	}
	var private crypto.Signer
	var err error
	switch algorithm {
	case "ECDSA_P256":
		private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "RSA_3072":
		private, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		return KeyReference{}, fmt.Errorf("unsupported key algorithm %q", algorithm)
	}
	if err != nil {
		return KeyReference{}, fmt.Errorf("generate private key: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return KeyReference{}, err
	}
	b, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return KeyReference{}, err
	}
	id, err := newID()
	if err != nil {
		return KeyReference{}, err
	}
	if err := s.write(id, b); err != nil {
		return KeyReference{}, err
	}
	return KeyReference{ID: id, Algorithm: algorithm}, nil
}
func (s *FileKeyStore) Sign(ctx context.Context, id string, data []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	private, err := s.load(id)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	switch key := private.(type) {
	case *rsa.PrivateKey:
		return key.Sign(rand.Reader, digest[:], crypto.SHA256)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, key, digest[:])
	default:
		return nil, errors.New("stored key is not a supported signing key")
	}
}
func (s *FileKeyStore) Delete(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := s.keyPath(id)
	if err != nil {
		return err
	}
	return os.Remove(path)
}
func (s *FileKeyStore) keyPath(id string) (string, error) {
	if !validID(id) {
		return "", errors.New("invalid key ID")
	}
	return filepath.Join(s.directory, id+".pk8"), nil
}
func (s *FileKeyStore) load(id string) (crypto.PrivateKey, error) {
	path, err := s.keyPath(id)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("stored private key is not a PKCS#8 PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}
func (s *FileKeyStore) write(id string, key []byte) error {
	target, err := s.keyPath(id)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.directory, ".key-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err = os.Rename(name, target); err != nil {
		return fmt.Errorf("store private key: %w", err)
	}
	return nil
}
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "key_" + hex.EncodeToString(b), nil
}
func validID(id string) bool {
	if !strings.HasPrefix(id, "key_") || len(id) != 36 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(id, "key_"))
	return err == nil
}
