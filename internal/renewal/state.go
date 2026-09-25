// Package renewal defines the certificate lifecycle. It does not perform key
// generation, issuance, or deployment; those operations must drive these
// transitions only after their safety checks succeed.
package renewal

import "fmt"

type State string

const (
	Discovered       State = "DISCOVERED"
	Registered       State = "REGISTERED"
	Healthy          State = "HEALTHY"
	RenewalRequired  State = "RENEWAL_REQUIRED"
	RenewalPending   State = "RENEWAL_PENDING"
	Issuing          State = "ISSUING"
	Issued           State = "ISSUED"
	Staged           State = "STAGED"
	Validating       State = "VALIDATING"
	Active           State = "ACTIVE"
	RenewalFailed    State = "RENEWAL_FAILED"
	DeploymentFailed State = "DEPLOYMENT_FAILED"
	ValidationFailed State = "VALIDATION_FAILED"
	RolledBack       State = "ROLLED_BACK"
)

var transitions = map[State]map[State]bool{
	Discovered:       {Registered: true},
	Registered:       {Healthy: true, RenewalRequired: true},
	Healthy:          {RenewalRequired: true},
	RenewalRequired:  {RenewalPending: true},
	RenewalPending:   {Issuing: true, RenewalFailed: true},
	Issuing:          {Issued: true, RenewalFailed: true},
	Issued:           {Staged: true, DeploymentFailed: true},
	Staged:           {Validating: true, DeploymentFailed: true},
	Validating:       {Active: true, ValidationFailed: true},
	ValidationFailed: {RolledBack: true},
	DeploymentFailed: {RolledBack: true},
	RenewalFailed:    {RenewalRequired: true},
	RolledBack:       {RenewalRequired: true},
}

// Transition rejects skipped and backward states so an operation cannot claim
// activation without having been staged and validated.
func Transition(from, to State) error {
	if from == to {
		return nil
	}
	if !transitions[from][to] {
		return fmt.Errorf("invalid certificate lifecycle transition: %s -> %s", from, to)
	}
	return nil
}

func Terminal(s State) bool { return s == Active || s == RolledBack }
