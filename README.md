# Adaptive Trust Certificates

Adaptive Trust Certificates (ATC) is a control plane for certificate inventory and lifecycle management. It works alongside X.509, TLS, OpenSSL, existing certificate authorities, and web servers; it does not replace them.

## Current vertical slice

This MVP provides a secure, runnable path from a Linux agent to the ATC control plane:

- an authenticated bootstrap enrollment flow that returns a per-agent bearer token;
- configurable certificate discovery and public X.509 inventory, including fingerprints, SANs, usage extensions, constraints, and observed chain length;
- bounded `openssl version -a` discovery with no shell interpolation;
- an inventory API scoped to the authenticated agent, plus operator-protected resource and audit views;
- expiry policy evaluation, expiring-certificate job scheduling, bounded retry with jitter, and signed HTTPS alert webhooks;
- confirmed, idempotent renewal and key-rotation jobs with pull-based agent execution; and
- agent-local CSR generation, development or HTTPS-issuer certificate issuance, staged deployment, rollback, Nginx validation, and TLS 1.3 service checks.

The server uses PostgreSQL and applies ordered SQL migrations at startup. `ATC_STORAGE=memory` is available only for unit tests or throwaway local development. The dashboard is intentionally small and same-origin; it has no private-key display or upload path. This remains a security-product prototype, not a production-ready service: it still needs independent security review, role-based authorization, operational hardening, and deployment testing before production use.

## Project status

ATC manages certificate inventory and lifecycle operations around established standards. It does not replace TLS, X.509, OpenSSL, a certificate authority, or a web server; it never creates custom cryptography. Private keys remain on the managed host and are excluded from inventory, APIs, logs, database records, and webhook payloads.

## Run locally

```sh
cp .env.example .env
# Set ATC_BOOTSTRAP_TOKEN and POSTGRES_PASSWORD in .env to distinct, long random values.
docker compose up --build -d
set -a; . ./.env; set +a
go run ./cmd/atc-agent -server http://127.0.0.1:8080 -bootstrap-token "$ATC_BOOTSTRAP_TOKEN" -token-file /var/lib/atc/agent-token -config /etc/atc/agent.yaml
```

Open `http://127.0.0.1:8080/`. A real agent token is written atomically with mode `0600`; the enrollment command does not print it and refuses a symlinked token path.

Copy [agent.example.yaml](deploy/agent.example.yaml) to the agent host and configure explicit certificate deployment targets before enabling renewal execution. The agent uses `certificate_paths` from that trusted file when `-config` is set.

For a local development-CA run, start the server with `ATC_DEV_CA_DIR` set to a protected directory. Then execute exactly one pending, non-rotation job by ID:

```sh
go run ./cmd/atc-agent -server http://127.0.0.1:8080 -token-file /var/lib/atc/agent-token -config /etc/atc/agent.yaml -execute-renewal renewal_example
```

Execution validates Nginx, reloads it, and requires a verified TLS 1.3 handshake. Certificate-only renewal uses the configured existing local key. Rotation stages and rolls back the configured private-key and certificate paths together.

For an opt-in long-running agent, use `-execute-pending -poll-interval 5m` with `-config`. Each cycle uploads inventory, retrieves only jobs belonging to that agent, and executes only certificate IDs explicitly mapped in the local configuration. It never derives deployment paths or private-key locations from server inventory. Run it under your host's service manager with restricted access to the configuration, token, and key directory.

To queue expiring certificates automatically, independently set `ATC_AUTO_RENEW=true` on the server. It creates one audited pending job per certificate inventory snapshot when the default expiry policy marks an agent-configured renewal target `EXPIRING` or `EXPIRED`. The agent reports only the target's public stable certificate ID, never its deployment path or key data. The server does not deploy anything by itself: deployment additionally requires an agent deliberately started with `-execute-pending` and a matching trusted local target.

The expiry windows are configurable through `ATC_POLICY_CRITICAL_HOURS`, `ATC_POLICY_HIGH_DAYS`, and `ATC_POLICY_MEDIUM_DAYS` (defaults: 24 hours, 7 days, and 30 days). All values must be positive and strictly ordered. The configured policy is used consistently for newly ingested certificates, API reads, high-risk alerts, and automatic renewal job creation.

To send alerts to an operations system, set both `ATC_ALERT_WEBHOOK_URL` and a long random `ATC_ALERT_WEBHOOK_SECRET`. The endpoint must be HTTPS with TLS 1.3. ATC sends a JSON body signed in `X-ATC-Signature` as `sha256=<hex HMAC>` and never includes private-key material or deployment paths. It emits `certificate_risk_detected` once for each accepted high/critical-risk inventory and `renewal_state_failed` when an agent reports a failed issuance, deployment, or validation transition. Verify the HMAC in constant time, enforce a timestamp freshness window, and deduplicate payload hashes in the receiver.

For an enterprise CA, configure `ATC_ISSUER_URL` with an HTTPS endpoint. It receives a JSON CSR request and returns `certificate_pem`, a full `chain_pem` beginning with the issued leaf, and `not_after`; configure `ATC_ISSUER_CA_FILE` and optional `ATC_ISSUER_CLIENT_CERT_FILE`/`ATC_ISSUER_CLIENT_KEY_FILE` for its TLS trust and mutual TLS. This is mutually exclusive with `ATC_DEV_CA_DIR`. ACME challenge orchestration is not included.

Inspect the control-plane state with the CLI:

```sh
go run ./cmd/atc certificates list
go run ./cmd/atc certificates inspect cert_example
go run ./cmd/atc renewals list
go run ./cmd/atc findings list
```

## OpenSSL vulnerability rules

Set `ATC_VULNERABILITY_RULES_FILE` to a reviewed JSON rule set before starting the server. The server refuses malformed, unsourced, duplicate, or unbounded rules and exposes matching results through `atc findings list`. [vulnerability-rules.example.json](deploy/vulnerability-rules.example.json) is syntax-only and must not be enabled as a real advisory source.

## Production transport

For a remote deployment, configure `ATC_TLS_CERT_FILE`, `ATC_TLS_KEY_FILE`, `ATC_TLS_CLIENT_CA_FILE`, and `ATC_REQUIRE_MTLS=true` on the server. ATC then serves TLS 1.3 only and requires a client certificate signed by the configured client CA.

Configure the agent and operator CLI with an HTTPS `-server` plus `-tls-ca-file`, `-tls-cert-file`, and `-tls-key-file` (or `ATC_TLS_CA_FILE`, `ATC_CLIENT_TLS_CERT_FILE`, and `ATC_CLIENT_TLS_KEY_FILE`). The client certificate and key are required together. Plain HTTP remains limited to literal loopback endpoints for local development.

Set a separate `ATC_OPERATOR_TOKEN` in any deployment. It protects operator reads, findings, renewal history, and renewal/rotation requests; provide it to the CLI with `ATC_OPERATOR_TOKEN` or `-token`.

If an agent is retired or compromised, disable its bearer credential while preserving its history with `atc agent revoke <agent-id>`.

## Security boundaries

- Private-key PEM blocks are ignored during scanning and are neither serialized nor logged.
- The bootstrap token is required only for registration; subsequent inventory calls require the agent token.
- Tokens are randomly generated and only SHA-256 token hashes are retained in PostgreSQL.
- Renewal, key generation, certificate installation, and service reload occur only in the trusted local agent workflow; they are not exposed as operator API operations.

See [docs/architecture.md](docs/architecture.md), [docs/api.md](docs/api.md), [docs/security-model.md](docs/security-model.md), and [docs/threat-model.md](docs/threat-model.md).

## License

ATC is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
