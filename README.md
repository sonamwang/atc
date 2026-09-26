# Adaptive Trust Certificates

Adaptive Trust Certificates (ATC) is a control plane for certificate inventory and lifecycle management. It works alongside X.509, TLS, OpenSSL, existing certificate authorities, and web servers; it does not replace them.

## Current vertical slice

This MVP provides a secure, runnable path from a Linux agent to the ATC control plane:

- an authenticated bootstrap enrollment flow that returns a per-agent bearer token;
- configurable certificate discovery and public X.509 inventory, including fingerprints, SANs, usage extensions, constraints, and observed chain length;
- bounded `openssl version -a` discovery with no shell interpolation;
- an inventory API scoped to the authenticated agent, plus named viewer/operator/admin access control for resource and audit views;
- expiry policy evaluation, expiring-certificate job scheduling, bounded retry with jitter, and signed HTTPS alert webhooks;
- confirmed, idempotent renewal and key-rotation jobs with pull-based agent execution; and
- agent-local CSR generation; development, HTTPS, or ACME HTTP-01 issuance; staged deployment and rollback; Nginx, Apache, and Kubernetes Deployment validation; and TLS 1.3 service checks.

The server uses PostgreSQL and applies ordered SQL migrations at startup. `ATC_STORAGE=memory` is available only for unit tests or throwaway local development. The dashboard is intentionally small and same-origin; it has no private-key display or upload path. This remains a security-product prototype: it still needs independent security review, operational hardening, and environment-specific deployment testing before production use.

## Project status

ATC manages certificate inventory and lifecycle operations around established standards. It does not replace TLS, X.509, OpenSSL, a certificate authority, or a web server; it never creates custom cryptography. Private keys remain on the managed host and are excluded from inventory, APIs, logs, database records, and webhook payloads.

## Run locally

ATC requires Go 1.25 or later. Docker Desktop is required only for the
PostgreSQL-backed Compose environment.

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

For an enterprise CA, configure `ATC_ISSUER_URL` with an HTTPS endpoint. It receives a JSON CSR request and returns `certificate_pem`, a full `chain_pem` beginning with the issued leaf, and `not_after`; configure `ATC_ISSUER_CA_FILE` and optional `ATC_ISSUER_CLIENT_CERT_FILE`/`ATC_ISSUER_CLIENT_KEY_FILE` for its TLS trust and mutual TLS. This is mutually exclusive with `ATC_DEV_CA_DIR`.

For public CA issuance, an agent renewal target can instead specify `issuer: acme_http01` and an explicit `acme` block. The agent creates or loads a local ECDSA account key at mode `0600`, writes a short-lived HTTP-01 response below the configured webroot, waits for authorization, then deletes the response. It accepts terms only when `terms_of_service_accepted: true` is present in trusted local configuration. HTTP-01 requires every DNS name to serve that webroot on public port 80; wildcard names require a DNS-01-capable issuer and are rejected.

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

## Operator roles

Use a local, mode-`0600` JSON credential file such as [operators.example.json](deploy/operators.example.json), then start the server with `ATC_OPERATOR_CREDENTIALS_FILE=/etc/atc/operators.json`. Token values are stored in memory only as SHA-256 hashes after startup. Each named account has one of these roles:

| Role | Permissions |
| --- | --- |
| `viewer` | Read inventory, audit records, renewal history, vulnerability findings, and CT lookup results. |
| `operator` | Viewer permissions plus renewal and rotation requests. |
| `admin` | Operator permissions plus agent revocation. |

Use `ATC_OPERATOR_TOKEN` only as a backward-compatible single-admin token. Supply a user’s token to the CLI with `ATC_OPERATOR_TOKEN` or `-token`; `atc whoami` shows the effective name and role. Renewal and revocation audit records now retain that named actor.

## Certificate Transparency

To opt in to external CT lookup, set `ATC_CT_MONITOR_URL` to an HTTPS URL template with exactly one `{domain}` query placeholder—for example `https://crt.sh/?q={domain}&output=json`. A viewer or higher can run `atc ct lookup api.example.com`. ATC validates the domain, uses TLS 1.3, limits the response size, and returns normalized public CT entries. CT services may reveal queried names to their operator, so leave this disabled when that disclosure is unacceptable.

## Apache and Kubernetes deployment targets

Set `service: apache` in a file deployment target to make the agent run fixed `apachectl -t`, `systemctl reload apache2`, and `systemctl is-active apache2` commands during the same staged rollback workflow used for Nginx.

For a Kubernetes workload, set `deployment: kubernetes_secret`, `service: kubernetes`, and its `kubernetes` block in trusted agent configuration. The agent uses only its local `kubectl`/service-account identity to read and apply the explicitly named Secret, preserves any unrelated Secret data, restarts the explicitly named Deployment, waits at most 90 seconds for rollout status, and rolls the Secret back if later validation fails. The control plane never receives kubeconfig contents, Secret data, or private keys.

## TPM and HSM-backed keys

Set `key_store: hardware_plugin` with a locked-down local signer executable to renew a certificate using a TPM/HSM key handle. ATC passes public CSR parameters to the plugin and validates the returned CSR, but it has no private-key export operation in this mode. This supports certificate-only renewal for a preconfigured service binding; it intentionally refuses rotations that would require writing a hardware key into a file or Kubernetes Secret. See [the hardware signer contract](docs/hardware-signer-plugin.md) for the small JSON protocol a TPM/HSM vendor adapter implements.

Cloud CA integrations use the existing mutually authenticated `ATC_ISSUER_URL` contract, so an organization can place its AWS, Azure, Google Cloud, or internal CA adapter behind that narrowly scoped HTTPS endpoint without giving ATC cloud account credentials. Kubernetes deployment likewise uses only the agent's locally supplied workload identity.

If an agent is retired or compromised, disable its bearer credential while preserving its history with `atc agent revoke <agent-id>`.

## Security boundaries

- Private-key PEM blocks are ignored during scanning and are neither serialized nor logged.
- The bootstrap token is required only for registration; subsequent inventory calls require the agent token.
- Tokens are randomly generated and only SHA-256 token hashes are retained in PostgreSQL.
- Renewal, key generation, certificate installation, and service reload occur only in the trusted local agent workflow; they are not exposed as operator API operations.

See [docs/architecture.md](docs/architecture.md), [docs/api.md](docs/api.md), [docs/security-model.md](docs/security-model.md), and [docs/threat-model.md](docs/threat-model.md).

## License

ATC is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
