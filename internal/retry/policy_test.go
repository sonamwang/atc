package retry

import (
	"testing"
	"time"
)

func TestDelayIsBoundedAndJittered(t *testing.T) {
	p := Policy{Initial: time.Second, Maximum: 5 * time.Second, MaxAttempts: 4, Jitter: .2}
	got, err := p.Delay(3, func() float64 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	if got != 4800*time.Millisecond {
		t.Fatalf("delay=%s", got)
	}
	got, err = p.Delay(4, func() float64 { return 0 })
	if err != nil {
		t.Fatal(err)
	}
	if got != 4*time.Second {
		t.Fatalf("bounded delay=%s", got)
	}
}
func TestDelayRejectsUnboundedAttempts(t *testing.T) {
	if _, err := Default().Delay(7, func() float64 { return .5 }); err == nil {
		t.Fatal("out of bounds attempt accepted")
	}
}
