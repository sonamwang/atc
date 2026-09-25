package openssl

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

type Info struct {
	Version  string `json:"version"`
	Build    string `json:"build"`
	Platform string `json:"platform"`
}

func Discover(ctx context.Context) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "openssl", "version", "-a").Output()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Info{}, errors.New("openssl command timed out")
	}
	if err != nil {
		return Info{}, errors.New("openssl unavailable or failed")
	}
	lines := strings.Split(string(out), "\n")
	var i Info
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "OpenSSL "):
			i.Version = line
		case strings.HasPrefix(line, "built on:"):
			i.Build = strings.TrimSpace(strings.TrimPrefix(line, "built on:"))
		case strings.HasPrefix(line, "platform:"):
			i.Platform = strings.TrimSpace(strings.TrimPrefix(line, "platform:"))
		}
	}
	if i.Version == "" {
		return Info{}, errors.New("malformed openssl output")
	}
	return i, nil
}
