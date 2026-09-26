# Initial Architecture

The first slice has three trust boundaries: agent enrollment, authenticated inventory upload, and server-side presentation. The agent reads certificate files locally and sends only parsed public certificate metadata. Private key blocks are skipped by the PEM parser and are not represented in the inventory contract.

The server receives a bootstrap credential only on registration and returns a random agent token. It stores only the SHA-256 hash of that token in PostgreSQL. Inventory requests are scoped to the authenticated agent, so a caller cannot nominate a different agent or asset owner. Ordered migrations are recorded in `schema_migrations` and run in transactions at startup.

The API uses JSON over HTTP for local development. Before deployment beyond local development, enable mutually authenticated TLS, use an external secret manager for bootstrap credentials, configure named operator RBAC, and complete independent security review.

## Renewal lifecycle foundation

`internal/renewal` declares the only valid certificate lifecycle transitions. In particular, `ISSUED` cannot become `ACTIVE` directly: it must be staged and validated first. Failure during validation or deployment must enter a failure state and then `ROLLED_BACK`. The `renewal_jobs` schema records an idempotency key and prevents concurrent active jobs for one certificate.

## Local renewal worker

The worker is now implemented as an agent-local component. It creates a CSR with the local `FileKeyStore`, asks a configured issuer for a certificate, verifies the replacement's SANs and expiry, writes a staged certificate within an allowed directory, then activates it for Nginx validation and reload. It retains the previous certificate until the service is active, and restores it if validation or reload fails. A rollback is recorded only after the restore reload succeeds.

The worker also restores the previous certificate if it cannot record either the validating or final active lifecycle state after activation. It records the final active state before deleting backup material, so cleanup failures do not cause a known-good live certificate to be rolled back.

Deployment targets are explicit in trusted agent configuration. File targets support Nginx and Apache service providers; Kubernetes targets use a locally authenticated `kubectl` transaction against a named Secret and Deployment. File keys use the built-in local key store; TPM/HSM keys use an agent-local signer plugin that returns only public CSRs and signatures. The server can delegate issuance to a configured HTTPS CSR issuer with its own trust bundle and client certificate, while a local agent can use ACME HTTP-01 when a configured webroot is publicly served. The worker verifies that the issued certificate public key matches the locally generated CSR, is valid for TLS server use, and has a linked full certificate chain before staging. The local `DevelopmentCA` is exclusively for local development and integration testing.

## Renewal dispatch protocol

The server now exposes a pull-based dispatch API. An agent token can retrieve only `RENEWAL_PENDING` jobs attached to its own assets. State updates require both the expected current state and a valid next state, are serialized by the database row lock, and produce an audit event. This prevents one agent from changing another agent's certificate lifecycle and avoids stale updates overwriting newer results.

The agent does not automatically execute a dispatched job by default. It only executes a named job after the operator supplies trusted deployment-target and local-key configuration; no operational target is inferred from untrusted inventory paths. TLS 1.3 mutual TLS can be enabled for the transport, but production issuer integration remains a boundary.

For controlled automation, the agent can be explicitly started with `-execute-pending`. It uploads a fresh inventory and processes pending jobs serially at the configured interval, but still requires a trusted local mapping for every certificate and validates/reloads the local service for each job. Failed jobs are reported independently so one bad target does not stop later eligible jobs. This mode should be managed by the host service manager; it is off by default.

The server can independently enable `ATC_AUTO_RENEW=true`. Its scheduler creates an audited `RENEWAL_PENDING` job for an expired or expiring certificate only once per inventory snapshot, and only if the owning agent explicitly reported that stable certificate ID from a trusted local renewal target. The same validated policy set by `ATC_POLICY_CRITICAL_HOURS`, `ATC_POLICY_HIGH_DAYS`, and `ATC_POLICY_MEDIUM_DAYS` drives inventory evaluation, API reads, alerts, and scheduling. It creates no deployment action. Automatic replacement therefore needs two explicit controls: server-side job creation and agent-side pending-job execution.

Renewal-target mappings use the stable certificate identifier derived from the owning asset and configured certificate path. A changed certificate fingerprint therefore updates the same asset record instead of invalidating the mapping after every renewal.

With a trusted mapping, the operator may explicitly select one job using `atc-agent -execute-renewal <id>`. The agent generates a CSR with its local key, the server's opt-in development CA returns only certificate material, and the worker stages, validates, reloads, and TLS-checks the service before retaining the replacement. For a rotation job, it stages and rolls back the configured key and certificate files together; private-key material stays in the agent process.
