package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOperatorAuthorizerEnforcesRoles(t *testing.T) {
	authorizer, err := NewOperatorAuthorizer([]Credential{
		{Name: "alice", Role: RoleViewer, Token: "a-long-viewer-token"},
		{Name: "ben", Role: RoleOperator, Token: "a-long-operator-token"},
		{Name: "casey", Role: RoleAdmin, Token: "a-long-admin-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if principal, ok := authorizer.Authorize("a-long-viewer-token", View); !ok || principal.Name != "alice" {
		t.Fatalf("viewer read = %#v, %v", principal, ok)
	}
	if _, ok := authorizer.Authorize("a-long-viewer-token", Renew); ok {
		t.Fatal("viewer was allowed to renew")
	}
	if _, ok := authorizer.Authorize("a-long-operator-token", Revoke); ok {
		t.Fatal("operator was allowed to revoke")
	}
	if principal, ok := authorizer.Authorize("a-long-admin-token", Revoke); !ok || principal.Role != RoleAdmin {
		t.Fatalf("admin revoke = %#v, %v", principal, ok)
	}
}

func TestLoadOperatorAuthorizerRejectsUnsafeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operators.json")
	if err := os.WriteFile(path, []byte(`[{"name":"alice","role":"admin","token":"a-long-admin-token"}]`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperatorAuthorizer(path); err == nil {
		t.Fatal("world-readable credential file was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperatorAuthorizer(path); err != nil {
		t.Fatalf("safe credential file rejected: %v", err)
	}
}
