// Package transport defines control-plane transport boundaries.
package transport

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ValidateControlPlaneURL accepts HTTPS endpoints and the explicit loopback
// HTTP exception used for local development. It does not resolve DNS names:
// allowing a hostname that happens to resolve to loopback would make this
// boundary dependent on mutable DNS state.
func ValidateControlPlaneURL(raw string) error {
	endpoint, err := url.ParseRequestURI(raw)
	if err != nil {
		return fmt.Errorf("parse control-plane URL: %w", err)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return errors.New("control-plane URL must use https, or http on loopback for local development")
	}
	if endpoint.Host == "" || endpoint.Hostname() == "" || endpoint.User != nil {
		return errors.New("control-plane URL must include a host and must not contain user credentials")
	}
	if endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("control-plane URL must not contain a query or fragment")
	}
	if endpoint.Scheme == "http" && !isLoopbackHost(endpoint.Hostname()) {
		return errors.New("remote control-plane URLs must use https")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
