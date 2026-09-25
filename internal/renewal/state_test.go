package renewal

import "testing"

func TestLifecycleAllowsSafePath(t *testing.T) {
	states := []State{Discovered, Registered, Healthy, RenewalRequired, RenewalPending, Issuing, Issued, Staged, Validating, Active}
	for i := 0; i < len(states)-1; i++ {
		if err := Transition(states[i], states[i+1]); err != nil {
			t.Fatalf("%s -> %s: %v", states[i], states[i+1], err)
		}
	}
}
func TestLifecycleRejectsUnsafeActivation(t *testing.T) {
	if err := Transition(Issued, Active); err == nil {
		t.Fatal("issued certificate must not become active without staging and validation")
	}
}
func TestLifecycleRequiresRollbackAfterValidationFailure(t *testing.T) {
	if err := Transition(ValidationFailed, RolledBack); err != nil {
		t.Fatal(err)
	}
}
