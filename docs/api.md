# Initial API

`GET /api/v1/health` returns the version and does not require authentication.

`POST /api/v1/agents/register` requires `Authorization: Bearer <bootstrap-token>` and accepts `name`, `hostname`, and `version`. It returns an agent object and a single returned agent token. The token is intentionally not repeatable.

`POST /api/v1/agents/{id}/revoke` disables the agent credential without removing its inventory or audit history. It requires operator authorization (or the bootstrap credential in local-development mode) and `X-ATC-Confirm: revoke`. Repeating a revocation is safe.

`GET /api/v1/agents/{id}`, `GET /api/v1/assets/{id}`, and `GET /api/v1/renewals/{id}` return exactly one corresponding public record or `404`. They have the same operator authorization boundary as their collection endpoints.

`POST /api/v1/inventory` requires `Authorization: Bearer <agent-token>`. Its asset owner is derived from the authenticated agent; the payload cannot select another agent. The body includes `hostname`, `operating_system`, `openssl_version`, and public certificate records.

Each certificate record must have a clean absolute observed path, valid time range, SHA-256 hexadecimal fingerprint, bounded public fields, and unique bounded SAN values. `renewable_certificate_ids` may contain only public stable IDs and is used to opt in matching records to automatic job creation; the agent derives it from trusted local target configuration. Malformed inventory is rejected before storage. This validates data shape only; it does not make agent claims cryptographic proof.

JSON request bodies are limited to 2 MiB, reject unknown fields, and must contain exactly one JSON object.

`POST /api/v1/certificates/{id}/renew` and `POST /api/v1/certificates/{id}/rotate` create a pending renewal job only. They require the bootstrap bearer credential, `X-ATC-Confirm: renewal`, and a constrained `Idempotency-Key`. Repeating the same request returns the original job; a second active job for the same certificate is rejected. No certificate, key, or service configuration is changed by these endpoints yet.

`GET /api/v1/certificates/{id}` returns one certificate record, including its stable certificate identifier, public metadata, key usage, extended key usage, basic constraints, observed chain length, first discovery timestamp, policy status, and observed path. It returns `404` when the certificate is absent. A PEM full-chain deployment file is represented as its first certificate plus the chain length, avoiding duplicate managed records for the same path.

Certificate policy is evaluated when inventory is read, using the current time. Expiry risk therefore advances even before an agent's next inventory upload; audit events remain historical records of the policy result at ingestion time.

The server validates `ATC_POLICY_CRITICAL_HOURS`, `ATC_POLICY_HIGH_DAYS`, and `ATC_POLICY_MEDIUM_DAYS` at startup. Those positive, ordered values are used for inventory evaluation and certificate reads, rather than changing historical audit records.

`GET /api/v1/agents` includes `inventory_status`: `FRESH` when the authenticated agent last uploaded inventory within 15 minutes, `STALE` after that threshold, or `UNKNOWN` for an invalid future or absent timestamp. It describes inventory freshness, not host reachability.

`GET /api/v1/findings` evaluates each asset's reported OpenSSL version against the reviewed rules loaded through `ATC_VULNERABILITY_RULES_FILE`. An absent or unsupported version produces an `UNVERIFIABLE_OPENSSL_VERSION` finding; a valid version with no matching enabled rules produces no finding.

`GET /api/v1/renewals` returns the pending-job inventory.

`GET /api/v1/agent/renewals` requires an agent bearer token and returns only renewal commands for certificates owned by that agent's asset. `POST /api/v1/agent/renewals/{id}/state` requires the same token and accepts the expected `from` lifecycle state and the requested `to` state. The server checks agent ownership, rejects stale state updates, and accepts only a declared lifecycle transition.

When both `ATC_ALERT_WEBHOOK_URL` and `ATC_ALERT_WEBHOOK_SECRET` are configured, the server also posts signed alert events to the configured HTTPS endpoint. The JSON body has `type`, `severity`, optional public `asset_id`, `certificate_id`, or `renewal_job_id`, `message`, and `occurred_at`. `X-ATC-Signature` is `sha256=` followed by the lowercase hexadecimal HMAC-SHA256 of the exact body, using the configured secret. The endpoint receives high/critical inventory summaries and failed renewal-state transitions; it is not an API callback and cannot change ATC state.

When `ATC_OPERATOR_TOKEN` is configured, `GET /api/v1/agents`, `/assets`, `/certificates`, `/findings`, `/renewals`, and `/audit`, plus renewal/rotation requests, require `Authorization: Bearer <operator-token>`. Without it, these read endpoints remain in local-development mode. The dashboard accepts the token in its form and keeps it only in the browser session. Role-based authorization remains future work.
