# Certificate Lifecycle

ATC records the following renewal states: `RENEWAL_PENDING`, `ISSUING`, `ISSUED`, `STAGED`, `VALIDATING`, and `ACTIVE`. Failure during issuance becomes `RENEWAL_FAILED`; failure after deployment begins becomes `VALIDATION_FAILED` followed by `ROLLED_BACK` only after the original certificate is restored and the service reload succeeds.

Renewal requests require an idempotency key. The database permits only one active job for a certificate. Retry timing is bounded exponential backoff with jitter: 30 seconds, 1 minute, 2 minutes, 5 minutes, 10 minutes, and 30 minutes by default.

The implementation supports explicit certificate-only renewal with an existing agent-local key and key rotation. Rotation stages the new local key and replacement certificate, retains both old files until validation succeeds, and restores both on validation or service failure.
