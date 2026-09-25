package services

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

type TLSValidator interface{ Validate(context.Context) error }
type EndpointValidator struct {
	address string
	config  *tls.Config
}

func NewTLSValidator(address, serverName, caFile string) (*EndpointValidator, error) {
	if address == "" || serverName == "" {
		return nil, errors.New("TLS address and server name are required")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read TLS CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("TLS CA file contains no certificates")
		}
	}
	return &EndpointValidator{address: address, config: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots}}, nil
}
func (v *EndpointValidator) Validate(ctx context.Context) error {
	connection, err := (&tls.Dialer{Config: v.config}).DialContext(ctx, "tcp", v.address)
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer connection.Close()
	state := connection.(*tls.Conn).ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
		return errors.New("TLS peer chain was not verified")
	}
	return nil
}
