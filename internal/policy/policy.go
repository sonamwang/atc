package policy

import (
	"fmt"
	"strings"
	"time"
)

type Policy struct{ CriticalHours, HighDays, MediumDays int }
type Result struct {
	Status string `json:"status"`
	Risk   string `json:"risk"`
	Reason string `json:"reason"`
}

func Default() Policy { return Policy{CriticalHours: 24, HighDays: 7, MediumDays: 30} }

// Validate keeps expiry windows ordered so each result category is reachable.
func (p Policy) Validate() error {
	if p.CriticalHours <= 0 || p.HighDays <= 0 || p.MediumDays <= 0 {
		return fmt.Errorf("certificate policy periods must be positive")
	}
	if p.HighDays <= p.CriticalHours/24 {
		return fmt.Errorf("certificate policy high_days must exceed critical_hours")
	}
	if p.MediumDays <= p.HighDays {
		return fmt.Errorf("certificate policy medium_days must exceed high_days")
	}
	return nil
}

func (p Policy) Evaluate(notAfter time.Time, signature string, keyBits int, now time.Time) Result {
	d := notAfter.Sub(now)
	if d <= 0 {
		return Result{"EXPIRED", "CRITICAL", "Certificate is expired"}
	}
	if d < time.Duration(p.CriticalHours)*time.Hour {
		return Result{"EXPIRING", "CRITICAL", fmt.Sprintf("Certificate expires in less than %d hours", p.CriticalHours)}
	}
	if d < time.Duration(p.HighDays)*24*time.Hour {
		return Result{"EXPIRING", "HIGH", fmt.Sprintf("Certificate expires in less than %d days", p.HighDays)}
	}
	if d < time.Duration(p.MediumDays)*24*time.Hour {
		return Result{"EXPIRING", "MEDIUM", fmt.Sprintf("Certificate expires in less than %d days", p.MediumDays)}
	}
	if strings.Contains(strings.ToUpper(signature), "SHA1") || keyBits > 0 && keyBits < 2048 {
		return Result{"WEAK", "HIGH", "Weak signature algorithm or public key size"}
	}
	return Result{"HEALTHY", "LOW", "Certificate is within the configured validity window"}
}
