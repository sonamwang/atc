package deployment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStageActivateRollback(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "server.pem")
	if err := os.WriteFile(target, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	d, err := NewFileDeployer([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	stage, err := d.Stage(target, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.Activate(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Fatalf("active=%q", b)
	}
	if err := stage.Rollback(); err != nil {
		t.Fatal(err)
	}
	b, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "old" {
		t.Fatalf("rolled back=%q", b)
	}
}
func TestRejectsPathOutsideRootAndSymlink(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.pem")
	if err := os.WriteFile(outside, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	d, err := NewFileDeployer([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Stage(outside, []byte("new")); err == nil {
		t.Fatal("outside root accepted")
	}
	link := filepath.Join(root, "link.pem")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Stage(link, []byte("new")); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestStagePairReplacesAndRollsBackKeyAndCertificate(t *testing.T) {
	root := t.TempDir()
	certificate := filepath.Join(root, "server.pem")
	key := filepath.Join(root, "server.key")
	if err := os.WriteFile(certificate, []byte("old cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("old key"), 0600); err != nil {
		t.Fatal(err)
	}
	deployer, err := NewFileDeployer([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := deployer.StagePair(certificate, key, []byte("new cert"), []byte("new key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pair.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := pair.Rollback(); err != nil {
		t.Fatal(err)
	}
	certificateData, _ := os.ReadFile(certificate)
	keyData, _ := os.ReadFile(key)
	if string(certificateData) != "old cert" || string(keyData) != "old key" {
		t.Fatalf("rollback mismatch: %q / %q", certificateData, keyData)
	}
}
