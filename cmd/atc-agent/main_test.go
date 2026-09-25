package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteTokenUsesRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "agent-token")
	if err := writeToken(path, "secret-value"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "secret-value\n" {
		t.Fatalf("token contents = %q", b)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("token mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestWriteTokenRefusesSymlink(t *testing.T) {
	directory := t.TempDir()
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("do not replace"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent-token")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := writeToken(path, "secret-value"); err == nil {
		t.Fatal("symlinked token path accepted")
	}
	contents, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "do not replace" {
		t.Fatalf("symlink target changed: %q", contents)
	}
}
