package keys

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// HardwareRunner is a narrow adapter for TPM/HSM middleware. The plugin is
// local to the agent and receives JSON through stdin; no private key bytes are
// ever returned to ATC or included in the protocol.
type HardwareRunner interface {
	Run(context.Context, []byte) ([]byte, error)
}

type hardwareCommandRunner struct{ path string }

func (r hardwareCommandRunner) Run(ctx context.Context, input []byte) ([]byte, error) {
	command := exec.CommandContext(ctx, r.path)
	command.Stdin = bytes.NewReader(input)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, err
	}
	output, readErr := io.ReadAll(io.LimitReader(stdout, 256<<10))
	waitErr := command.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if len(output) == 256<<10 {
		return nil, errors.New("hardware signer response exceeds 256 KiB")
	}
	if waitErr != nil {
		return nil, errors.New("hardware signer plugin failed")
	}
	return output, nil
}

// HardwareKeyStore supports TPM/HSM providers via a local signer plugin. The
// plugin owns the key handle and produces CSRs, so this store cannot export a
// private-key PEM. Certificate-only renewals work; key rotation requires a
// service-specific hardware-key binding workflow outside file deployment.
type HardwareKeyStore struct{ runner HardwareRunner }

func NewHardwareKeyStore(pluginPath string) (*HardwareKeyStore, error) {
	if pluginPath == "" || !filepath.IsAbs(pluginPath) {
		return nil, errors.New("hardware signer plugin must be an absolute path")
	}
	info, err := os.Lstat(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("inspect hardware signer plugin: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("hardware signer plugin must be a non-symlink regular file not writable by group or world")
	}
	return NewHardwareKeyStoreWithRunner(hardwareCommandRunner{path: pluginPath})
}

func NewHardwareKeyStoreWithRunner(runner HardwareRunner) (*HardwareKeyStore, error) {
	if runner == nil {
		return nil, errors.New("hardware signer runner is required")
	}
	return &HardwareKeyStore{runner: runner}, nil
}

func (s *HardwareKeyStore) GenerateKey(ctx context.Context, request KeyRequest) (KeyReference, error) {
	algorithm := request.Algorithm
	if algorithm == "" {
		algorithm = "ECDSA_P256"
	}
	if algorithm != "ECDSA_P256" && algorithm != "RSA_3072" {
		return KeyReference{}, fmt.Errorf("unsupported key algorithm %q", algorithm)
	}
	var response pluginResponse
	if err := s.call(ctx, pluginRequest{Operation: "generate", Algorithm: algorithm}, &response); err != nil {
		return KeyReference{}, err
	}
	if !validHardwareKeyID(response.KeyID) || response.Algorithm != algorithm {
		return KeyReference{}, errors.New("hardware signer returned invalid key reference")
	}
	return KeyReference{ID: response.KeyID, Algorithm: response.Algorithm}, nil
}

func (s *HardwareKeyStore) CreateCSR(ctx context.Context, id string, request CSRRequest) ([]byte, error) {
	if !validHardwareKeyID(id) || len(request.DNSNames) == 0 {
		return nil, errors.New("hardware CSR requires a valid key ID and at least one DNS SAN")
	}
	var response pluginResponse
	if err := s.call(ctx, pluginRequest{Operation: "create_csr", KeyID: id, CommonName: request.Subject.CommonName, DNSNames: request.DNSNames}, &response); err != nil {
		return nil, err
	}
	csr, err := parseCSR(response.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("hardware signer returned invalid CSR: %w", err)
	}
	if csr.Subject.CommonName != request.Subject.CommonName || !sameDNSNames(csr.DNSNames, request.DNSNames) {
		return nil, errors.New("hardware signer CSR does not match requested identity")
	}
	return []byte(response.CSRPEM), nil
}

func (s *HardwareKeyStore) PrivateKeyPEMForLocalDeployment(context.Context, string) ([]byte, error) {
	return nil, errors.New("hardware-backed private keys are non-exportable")
}

func (s *HardwareKeyStore) Sign(ctx context.Context, id string, data []byte) ([]byte, error) {
	if !validHardwareKeyID(id) || len(data) > 1<<20 {
		return nil, errors.New("invalid hardware signing request")
	}
	var response pluginResponse
	if err := s.call(ctx, pluginRequest{Operation: "sign", KeyID: id, DataBase64: base64.StdEncoding.EncodeToString(data)}, &response); err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(response.SignatureBase64)
	if err != nil || len(signature) == 0 || len(signature) > 64<<10 {
		return nil, errors.New("hardware signer returned invalid signature")
	}
	return signature, nil
}

func (s *HardwareKeyStore) Delete(ctx context.Context, id string) error {
	if !validHardwareKeyID(id) {
		return errors.New("invalid hardware key ID")
	}
	return s.call(ctx, pluginRequest{Operation: "delete", KeyID: id}, &pluginResponse{})
}

type pluginRequest struct {
	Operation  string   `json:"operation"`
	Algorithm  string   `json:"algorithm,omitempty"`
	KeyID      string   `json:"key_id,omitempty"`
	CommonName string   `json:"common_name,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	DataBase64 string   `json:"data_base64,omitempty"`
}
type pluginResponse struct {
	KeyID           string `json:"key_id,omitempty"`
	Algorithm       string `json:"algorithm,omitempty"`
	CSRPEM          string `json:"csr_pem,omitempty"`
	SignatureBase64 string `json:"signature_base64,omitempty"`
}

func (s *HardwareKeyStore) call(ctx context.Context, request pluginRequest, result *pluginResponse) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	output, err := s.runner.Run(ctx, encoded)
	if err != nil {
		return fmt.Errorf("call hardware signer: %w", err)
	}
	if err := json.Unmarshal(output, result); err != nil {
		return errors.New("hardware signer returned invalid JSON")
	}
	return nil
}

func validHardwareKeyID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, char := range id {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == ':' || char == '-' || char == '/') {
			return false
		}
	}
	return true
}

func parseCSR(encoded string) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("not one certificate request PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	return csr, nil
}

func sameDNSNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	remaining := make(map[string]int, len(left))
	for _, value := range left {
		remaining[strings.ToLower(value)]++
	}
	for _, value := range right {
		key := strings.ToLower(value)
		if remaining[key] == 0 {
			return false
		}
		remaining[key]--
	}
	return true
}

var _ KeyStore = (*HardwareKeyStore)(nil)
