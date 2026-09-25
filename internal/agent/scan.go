package agent

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/adaptive-trust/atc/internal/certificates"
)

var extensions = map[string]bool{".crt": true, ".pem": true, ".cer": true, ".der": true}

// Scan only follows ordinary files below explicitly configured paths. It does not follow directory symlinks.
func Scan(ctx context.Context, roots []string) ([]certificates.Record, []string) {
	seen := map[string]bool{}
	var records []certificates.Record
	var warnings []string
	for _, root := range roots {
		info, err := os.Lstat(root)
		if err != nil {
			warnings = append(warnings, root+": "+err.Error())
			continue
		}
		if !info.IsDir() {
			records, warnings = scanFile(ctx, root, records, warnings, seen)
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				warnings = append(warnings, path+": "+err.Error())
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			records, warnings = scanFile(ctx, path, records, warnings, seen)
			return nil
		})
	}
	return records, warnings
}
func scanFile(ctx context.Context, path string, out []certificates.Record, warnings []string, seen map[string]bool) ([]certificates.Record, []string) {
	if ctx.Err() != nil {
		return out, warnings
	}
	if !extensions[strings.ToLower(filepath.Ext(path))] {
		return out, warnings
	}
	if seen[path] {
		return out, warnings
	}
	seen[path] = true
	info, err := os.Stat(path)
	if err != nil {
		return out, append(warnings, path+": "+err.Error())
	}
	if info.Size() > 10<<20 {
		return out, append(warnings, path+": file exceeds 10 MiB limit")
	}
	records, err := certificates.ParseFile(path)
	if err != nil {
		return out, append(warnings, path+": "+err.Error())
	}
	return append(out, records...), warnings
}
