package issuer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme"
)

// ACMEHTTP01Config contains only agent-local challenge and account details.
// It must come from the trusted agent YAML, never from inventory or an ATC API
// response. HTTP-01 requires that the configured webroot is served for the
// certificate's DNS names on public TCP port 80.
type ACMEHTTP01Config struct {
	DirectoryURL           string
	Email                  string
	AccountKeyFile         string
	Webroot                string
	TermsOfServiceAccepted bool
}

type ACMEHTTP01Issuer struct {
	config ACMEHTTP01Config
}

func NewACMEHTTP01Issuer(config ACMEHTTP01Config) (*ACMEHTTP01Issuer, error) {
	parsed, err := url.Parse(config.DirectoryURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("ACME directory URL must be an absolute HTTPS URL without credentials or fragment")
	}
	if strings.TrimSpace(config.Email) == "" || !strings.Contains(config.Email, "@") {
		return nil, errors.New("ACME account email is required")
	}
	if !config.TermsOfServiceAccepted {
		return nil, errors.New("ACME terms_of_service_accepted must be explicitly true")
	}
	for _, entry := range []struct{ name, path string }{{"ACME account key file", config.AccountKeyFile}, {"ACME HTTP-01 webroot", config.Webroot}} {
		if entry.path == "" || !filepath.IsAbs(entry.path) {
			return nil, fmt.Errorf("%s must be an absolute path", entry.name)
		}
	}
	config.AccountKeyFile = filepath.Clean(config.AccountKeyFile)
	config.Webroot = filepath.Clean(config.Webroot)
	if info, err := os.Lstat(config.Webroot); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("ACME HTTP-01 webroot must be an existing non-symlink directory")
	}
	return &ACMEHTTP01Issuer{config: config}, nil
}

func (i *ACMEHTTP01Issuer) Issue(ctx context.Context, request CertificateRequest) (CertificateResult, error) {
	csr, err := parseCSR(request.CSRPEM)
	if err != nil {
		return CertificateResult{}, err
	}
	if len(csr.DNSNames) == 0 {
		return CertificateResult{}, errors.New("ACME HTTP-01 requires at least one DNS SAN")
	}
	identifiers := make([]acme.AuthzID, 0, len(csr.DNSNames))
	for _, name := range csr.DNSNames {
		if strings.HasPrefix(name, "*.") {
			return CertificateResult{}, errors.New("ACME HTTP-01 cannot issue wildcard certificates; use a DNS-01-capable issuer")
		}
		identifiers = append(identifiers, acme.AuthzID{Type: "dns", Value: name})
	}
	accountKey, err := loadOrCreateACMEAccountKey(i.config.AccountKeyFile)
	if err != nil {
		return CertificateResult{}, err
	}
	client := &acme.Client{DirectoryURL: i.config.DirectoryURL, Key: accountKey}
	if _, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + i.config.Email}}, acme.AcceptTOS); err != nil {
		return CertificateResult{}, fmt.Errorf("register ACME account: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, identifiers)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("create ACME order: %w", err)
	}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return CertificateResult{}, fmt.Errorf("retrieve ACME authorization: %w", err)
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		challenge := http01Challenge(authorization)
		if challenge == nil {
			return CertificateResult{}, fmt.Errorf("ACME authorization for %q did not offer HTTP-01", authorization.Identifier.Value)
		}
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			return CertificateResult{}, fmt.Errorf("create ACME HTTP-01 response: %w", err)
		}
		remove, err := writeHTTP01Challenge(i.config.Webroot, challenge.Token, response)
		if err != nil {
			return CertificateResult{}, err
		}
		if _, err = client.Accept(ctx, challenge); err != nil {
			remove()
			return CertificateResult{}, fmt.Errorf("accept ACME HTTP-01 challenge: %w", err)
		}
		_, waitErr := client.WaitAuthorization(ctx, authorizationURL)
		remove()
		if waitErr != nil {
			return CertificateResult{}, fmt.Errorf("wait for ACME authorization: %w", waitErr)
		}
	}
	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr.Raw, true)
	if err != nil {
		return CertificateResult{}, fmt.Errorf("finalize ACME order: %w", err)
	}
	if len(der) == 0 {
		return CertificateResult{}, errors.New("ACME issuer returned an empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return CertificateResult{}, fmt.Errorf("parse issued ACME certificate: %w", err)
	}
	chain := make([]byte, 0, len(der)*1024)
	for _, certificateDER := range der {
		if _, err := x509.ParseCertificate(certificateDER); err != nil {
			return CertificateResult{}, fmt.Errorf("parse ACME certificate chain: %w", err)
		}
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})...)
	}
	return CertificateResult{CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der[0]}), ChainPEM: chain, NotAfter: leaf.NotAfter}, nil
}

func parseCSR(encoded []byte) (*x509.CertificateRequest, error) {
	if len(encoded) == 0 || len(encoded) > 128<<10 {
		return nil, errors.New("CSR must be between 1 byte and 128 KiB")
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("request must contain exactly one PEM certificate signing request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify CSR signature: %w", err)
	}
	return csr, nil
}

func http01Challenge(authorization *acme.Authorization) *acme.Challenge {
	for _, challenge := range authorization.Challenges {
		if challenge.Type == "http-01" && challenge.Status == acme.StatusPending {
			return challenge
		}
	}
	return nil
}

func loadOrCreateACMEAccountKey(path string) (*ecdsa.PrivateKey, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("ACME account key must be a private regular non-symlink file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ACME account key: %w", err)
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, errors.New("ACME account key is not a single PKCS#8 private-key PEM block")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ACME account key: %w", err)
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ACME account key must be ECDSA")
		}
		return ecdsaKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect ACME account key: %w", err)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("create ACME account key directory: %w", err)
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("ACME account key directory must be a real directory")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ACME account key: %w", err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateACMEAccountKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create ACME account key: %w", err)
	}
	if _, err = file.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("write ACME account key: %w", err)
	}
	return key, nil
}

func writeHTTP01Challenge(webroot, token, response string) (func(), error) {
	if !validChallengeToken(token) {
		return nil, errors.New("ACME returned an invalid HTTP-01 challenge token")
	}
	directory := filepath.Join(webroot, ".well-known", "acme-challenge")
	if relative, err := filepath.Rel(webroot, directory); err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("ACME challenge directory escapes configured webroot")
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return nil, fmt.Errorf("create ACME challenge directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".atc-acme-")
	if err != nil {
		return nil, err
	}
	temporary := file.Name()
	if err = file.Chmod(0644); err == nil {
		_, err = file.WriteString(response)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temporary)
		return nil, fmt.Errorf("write ACME HTTP-01 response: %w", err)
	}
	target := filepath.Join(directory, token)
	if err = os.Rename(temporary, target); err != nil {
		_ = os.Remove(temporary)
		return nil, fmt.Errorf("publish ACME HTTP-01 response: %w", err)
	}
	return func() { _ = os.Remove(target) }, nil
}

func validChallengeToken(token string) bool {
	if len(token) == 0 || len(token) > 256 {
		return false
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

var _ CertificateIssuer = (*ACMEHTTP01Issuer)(nil)
