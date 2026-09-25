// Package retry provides bounded exponential retry timing for renewal work.
package retry

import (
	"errors"
	"math"
	"math/rand/v2"
	"time"
)

type Policy struct {
	Initial, Maximum time.Duration
	MaxAttempts      int
	Jitter           float64
}

func Default() Policy {
	return Policy{Initial: 30 * time.Second, Maximum: 30 * time.Minute, MaxAttempts: 6, Jitter: 0.2}
}
func (p Policy) Delay(attempt int, random func() float64) (time.Duration, error) {
	if p.Initial <= 0 || p.Maximum < p.Initial || p.MaxAttempts < 1 || p.Jitter < 0 || p.Jitter > 1 {
		return 0, errors.New("invalid retry policy")
	}
	if attempt < 1 || attempt > p.MaxAttempts {
		return 0, errors.New("retry attempt is outside policy bounds")
	}
	delay := float64(p.Initial) * math.Pow(2, float64(attempt-1))
	if delay > float64(p.Maximum) {
		delay = float64(p.Maximum)
	}
	if random == nil {
		random = rand.Float64
	}
	factor := 1 + p.Jitter*(2*random()-1)
	return time.Duration(delay * factor), nil
}
