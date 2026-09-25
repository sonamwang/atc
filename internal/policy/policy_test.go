package policy

import (
	"testing"
	"time"
)

func TestEvaluateExpiryBoundaries(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p := Default()
	for _, tc := range []struct {
		name    string
		expires time.Time
		want    string
	}{
		{"expired", now.Add(-time.Second), "EXPIRED"},
		{"critical", now.Add(2 * time.Hour), "CRITICAL"},
		{"high", now.Add(48 * time.Hour), "HIGH"},
		{"medium", now.Add(14 * 24 * time.Hour), "MEDIUM"},
		{"healthy", now.Add(60 * 24 * time.Hour), "LOW"},
	} {
		if got := p.Evaluate(tc.expires, "SHA256-RSA", 2048, now); got.Risk != tc.want && got.Status != tc.want {
			t.Fatalf("%s: got %#v", tc.name, got)
		}
	}
}

func TestPolicyValidationRequiresOrderedPositiveWindows(t *testing.T) {
	for _, candidate := range []Policy{
		{CriticalHours: 0, HighDays: 7, MediumDays: 30},
		{CriticalHours: 24, HighDays: 1, MediumDays: 30},
		{CriticalHours: 24, HighDays: 7, MediumDays: 7},
	} {
		if err := candidate.Validate(); err == nil {
			t.Fatalf("invalid policy accepted: %#v", candidate)
		}
	}
	if err := Default().Validate(); err != nil {
		t.Fatalf("default policy invalid: %v", err)
	}
}

func TestEvaluateExplainsConfiguredWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	configured := Policy{CriticalHours: 12, HighDays: 2, MediumDays: 10}
	result := configured.Evaluate(now.Add(6*time.Hour), "SHA256-RSA", 2048, now)
	if result.Reason != "Certificate expires in less than 12 hours" {
		t.Fatalf("configured reason = %q", result.Reason)
	}
}
