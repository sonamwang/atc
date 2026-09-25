package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ClientTLSConfig configures trust and an optional client certificate for the
// control-plane client. A certificate and key must be configured together.
type ClientTLSConfig struct {
	CAFile, CertificateFile, KeyFile string
}

// ServerTLSConfig configures a TLS 1.3 server. Supplying ClientCAFile makes
// client certificates mandatory and verified.
type ServerTLSConfig struct {
	CertificateFile, KeyFile, ClientCAFile string
	RequireClientCert                      bool
}

func NewHTTPClient(rawURL string, timeout time.Duration, config ClientTLSConfig) (*http.Client, error) {
	if err := ValidateControlPlaneURL(rawURL); err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse control-plane URL: %w", err)
	}
	configured := config.CAFile != "" || config.CertificateFile != "" || config.KeyFile != ""
	if endpoint.Scheme == "http" {
		if configured {
			return nil, errors.New("TLS client credentials require an https control-plane URL")
		}
		return &http.Client{Timeout: timeout}, nil
	}
	tlsConfig, err := loadClientTLSConfig(config)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: timeout, Transport: transport}, nil
}

func LoadServerTLSConfig(config ServerTLSConfig) (*tls.Config, error) {
	hasCertificate := config.CertificateFile != "" || config.KeyFile != ""
	if !hasCertificate {
		if config.ClientCAFile != "" || config.RequireClientCert {
			return nil, errors.New("server certificate and key are required for mutual TLS")
		}
		return nil, nil
	}
	if config.CertificateFile == "" || config.KeyFile == "" {
		return nil, errors.New("server certificate and key must be configured together")
	}
	if config.RequireClientCert && config.ClientCAFile == "" {
		return nil, errors.New("client CA file is required when mutual TLS is required")
	}
	certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server TLS certificate: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	if config.ClientCAFile != "" {
		pool, err := loadCertPool(config.ClientCAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsConfig, nil
}

func loadClientTLSConfig(config ClientTLSConfig) (*tls.Config, error) {
	if (config.CertificateFile == "") != (config.KeyFile == "") {
		return nil, errors.New("TLS client certificate and key must be configured together")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}
	if config.CAFile != "" {
		pool, err := loadCertPool(config.CAFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	if config.CertificateFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.CertificateFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return tlsConfig, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read TLS CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("TLS CA file contains no certificates")
	}
	return pool, nil
}
