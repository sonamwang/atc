package transport

import "testing"

func TestValidateControlPlaneURL(t *testing.T) {
	for _, raw := range []string{
		"https://atc.example.test",
		"https://atc.example.test/control-plane",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		if err := ValidateControlPlaneURL(raw); err != nil {
			t.Fatalf("%q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://atc.example.test",
		"ftp://atc.example.test",
		"https://user:password@atc.example.test",
		"https://atc.example.test?token=secret",
		"https:///missing-host",
	} {
		if err := ValidateControlPlaneURL(raw); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
}
