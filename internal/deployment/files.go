// Package deployment stages certificate files and provides explicit rollback.
package deployment

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type StagedFile struct {
	target, staged, backup string
	mode                   os.FileMode
}
type StagedPair struct{ certificate, key *StagedFile }
type FileDeployer struct{ roots []string }

// Staged is a reversible local deployment transaction. Implementations keep
// certificate and private-key bytes on the managed host.
type Staged interface {
	Activate() error
	Rollback() error
	Commit() error
	Discard() error
}

// Deployer supports trusted agent-local deployment targets.
type Deployer interface {
	Stage(string, []byte) (Staged, error)
	StagePair(string, string, []byte, []byte) (Staged, error)
}

func NewFileDeployer(roots []string) (*FileDeployer, error) {
	if len(roots) == 0 {
		return nil, errors.New("at least one allowed certificate root is required")
	}
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		out = append(out, filepath.Clean(abs))
	}
	return &FileDeployer{roots: out}, nil
}
func (d *FileDeployer) Stage(target string, contents []byte) (Staged, error) {
	return d.stage(target, contents)
}
func (d *FileDeployer) stage(target string, contents []byte) (*StagedFile, error) {
	path, err := d.allowed(target)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect target certificate: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("refusing to replace a symlinked certificate")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("certificate target is not a regular file")
	}
	nonce, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	stage := path + ".atc-stage-" + nonce
	f, err := os.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(contents); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(stage)
		return nil, fmt.Errorf("write staged certificate: %w", err)
	}
	return &StagedFile{target: path, staged: stage, backup: path + ".atc-backup-" + nonce, mode: info.Mode().Perm()}, nil
}
func (d *FileDeployer) StagePair(certificatePath, keyPath string, certificatePEM, keyPEM []byte) (Staged, error) {
	certificate, err := d.stage(certificatePath, certificatePEM)
	if err != nil {
		return nil, err
	}
	key, err := d.stage(keyPath, keyPEM)
	if err != nil {
		_ = certificate.Discard()
		return nil, err
	}
	return &StagedPair{certificate: certificate, key: key}, nil
}
func (s *StagedPair) Activate() error {
	if err := s.certificate.Activate(); err != nil {
		return err
	}
	if err := s.key.Activate(); err != nil {
		_ = s.certificate.Rollback()
		return fmt.Errorf("activate replacement key: %w", err)
	}
	return nil
}
func (s *StagedPair) Rollback() error {
	keyErr := s.key.Rollback()
	certificateErr := s.certificate.Rollback()
	if keyErr != nil || certificateErr != nil {
		return fmt.Errorf("rollback key: %v; rollback certificate: %v", keyErr, certificateErr)
	}
	return nil
}
func (s *StagedPair) Commit() error {
	keyErr := s.key.Commit()
	certificateErr := s.certificate.Commit()
	if keyErr != nil || certificateErr != nil {
		return fmt.Errorf("commit key: %v; commit certificate: %v", keyErr, certificateErr)
	}
	return nil
}
func (s *StagedPair) Discard() error {
	keyErr := s.key.Discard()
	certificateErr := s.certificate.Discard()
	if keyErr != nil || certificateErr != nil {
		return fmt.Errorf("discard key: %v; discard certificate: %v", keyErr, certificateErr)
	}
	return nil
}
func (s *StagedFile) Activate() error {
	if err := os.Rename(s.target, s.backup); err != nil {
		return fmt.Errorf("backup current certificate: %w", err)
	}
	if err := os.Rename(s.staged, s.target); err != nil {
		_ = os.Rename(s.backup, s.target)
		return fmt.Errorf("activate staged certificate: %w", err)
	}
	return nil
}
func (s *StagedFile) Rollback() error {
	if _, err := os.Stat(s.backup); err != nil {
		return fmt.Errorf("rollback backup unavailable: %w", err)
	}
	failed := s.target + ".atc-failed"
	if err := os.Rename(s.target, failed); err != nil {
		return err
	}
	if err := os.Rename(s.backup, s.target); err != nil {
		_ = os.Rename(failed, s.target)
		return fmt.Errorf("restore certificate backup: %w", err)
	}
	_ = os.Remove(failed)
	return nil
}
func (s *StagedFile) Commit() error {
	if err := os.Remove(s.backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (s *StagedFile) Discard() error {
	if err := os.Remove(s.staged); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func (d *FileDeployer) allowed(target string) (string, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	path := filepath.Clean(abs)
	for _, root := range d.roots {
		rel, err := filepath.Rel(root, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return path, nil
		}
	}
	return "", errors.New("certificate path is outside allowed roots")
}
func randomSuffix() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
