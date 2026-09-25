package main

import (
	"strings"
	"testing"
)

func TestAlertWebhookConfigRequiresCompletePair(t *testing.T) {
	secret := strings.Repeat("a", 32)
	if _, err := alertWebhookFromConfig("https://alerts.example.test/atc", ""); err == nil {
		t.Fatal("webhook URL without secret accepted")
	}
	if _, err := alertWebhookFromConfig("", secret); err == nil {
		t.Fatal("webhook secret without URL accepted")
	}
	webhook, err := alertWebhookFromConfig("https://alerts.example.test/atc", secret)
	if err != nil || webhook == nil {
		t.Fatalf("complete webhook configuration = %#v, %v", webhook, err)
	}
}

func TestPolicyFromEnvironmentValidatesConfiguredWindows(t *testing.T) {
	t.Setenv("ATC_POLICY_CRITICAL_HOURS", "12")
	t.Setenv("ATC_POLICY_HIGH_DAYS", "2")
	t.Setenv("ATC_POLICY_MEDIUM_DAYS", "10")
	value, err := policyFromEnvironment()
	if err != nil || value.CriticalHours != 12 || value.HighDays != 2 || value.MediumDays != 10 {
		t.Fatalf("configured policy = %#v, %v", value, err)
	}
	t.Setenv("ATC_POLICY_HIGH_DAYS", "0")
	if _, err := policyFromEnvironment(); err == nil {
		t.Fatal("invalid policy accepted")
	}
}
