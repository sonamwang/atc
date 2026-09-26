// Package auth implements control-plane operator authentication and RBAC.
// It deliberately does not authenticate agents; agent credentials are stored
// and verified by the repository because they are scoped to one managed host.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

type Permission string

const (
	View   Permission = "view"
	Renew  Permission = "renew"
	Revoke Permission = "revoke"
)

// Credential is intentionally loaded only from trusted local configuration.
// Token is never serialized by this package and is retained solely as a hash.
type Credential struct {
	Name  string `json:"name"`
	Role  Role   `json:"role"`
	Token string `json:"token"`
}

type Principal struct {
	Name string `json:"name"`
	Role Role   `json:"role"`
}

type credentialHash struct {
	principal Principal
	hash      [sha256.Size]byte
}

type OperatorAuthorizer struct{ credentials []credentialHash }

func NewOperatorAuthorizer(credentials []Credential) (*OperatorAuthorizer, error) {
	if len(credentials) == 0 {
		return nil, errors.New("at least one operator credential is required")
	}
	seenNames := make(map[string]struct{}, len(credentials))
	seenTokens := make(map[[sha256.Size]byte]struct{}, len(credentials))
	stored := make([]credentialHash, 0, len(credentials))
	for _, credential := range credentials {
		credential.Name = strings.TrimSpace(credential.Name)
		if !validName(credential.Name) {
			return nil, fmt.Errorf("invalid operator name %q", credential.Name)
		}
		if !validRole(credential.Role) {
			return nil, fmt.Errorf("invalid role %q", credential.Role)
		}
		if credential.Token == "" {
			return nil, fmt.Errorf("operator token for %q is required", credential.Name)
		}
		if _, ok := seenNames[credential.Name]; ok {
			return nil, fmt.Errorf("duplicate operator name %q", credential.Name)
		}
		hash := sha256.Sum256([]byte(credential.Token))
		if _, ok := seenTokens[hash]; ok {
			return nil, errors.New("operator tokens must be unique")
		}
		seenNames[credential.Name], seenTokens[hash] = struct{}{}, struct{}{}
		stored = append(stored, credentialHash{principal: Principal{Name: credential.Name, Role: credential.Role}, hash: hash})
	}
	sort.Slice(stored, func(i, j int) bool { return stored[i].principal.Name < stored[j].principal.Name })
	return &OperatorAuthorizer{credentials: stored}, nil
}

// LoadOperatorAuthorizer accepts a local JSON credential file. The file must
// be a regular, non-symlink file and must not be group/world readable.
func LoadOperatorAuthorizer(path string) (*OperatorAuthorizer, error) {
	if path == "" {
		return nil, errors.New("operator credentials file is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect operator credentials: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("operator credentials must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("operator credentials file must not be group or world accessible")
	}
	if info.Size() > 1<<20 {
		return nil, errors.New("operator credentials file exceeds 1 MiB")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read operator credentials: %w", err)
	}
	var credentials []Credential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return nil, fmt.Errorf("decode operator credentials: %w", err)
	}
	return NewOperatorAuthorizer(credentials)
}

func (a *OperatorAuthorizer) Authorize(token string, permission Permission) (Principal, bool) {
	if a == nil || token == "" {
		return Principal{}, false
	}
	candidate := sha256.Sum256([]byte(token))
	var result Principal
	matched := 0
	for _, credential := range a.credentials {
		equal := subtle.ConstantTimeCompare(candidate[:], credential.hash[:])
		allowed := 0
		if permits(credential.principal.Role, permission) {
			allowed = 1
		}
		if equal&allowed == 1 {
			result = credential.principal
		}
		matched |= equal & allowed
	}
	return result, matched == 1
}

func permits(role Role, permission Permission) bool {
	switch permission {
	case View:
		return role == RoleViewer || role == RoleOperator || role == RoleAdmin
	case Renew:
		return role == RoleOperator || role == RoleAdmin
	case Revoke:
		return role == RoleAdmin
	default:
		return false
	}
}

func validRole(role Role) bool {
	return role == RoleViewer || role == RoleOperator || role == RoleAdmin
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
