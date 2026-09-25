# Security Model

ATC separates its control plane from cryptographic operations. Agents parse public certificate data, retain private keys locally, and submit CSRs rather than keys. Renewal targets, key paths, TLS endpoints, and trust roots are local agent configuration; inventory data cannot select an operational file path.

Certificate inventory includes only public X.509 properties: identity, validity, fingerprint, SANs, usage extensions, basic constraints, and chain length. A full-chain PEM file is stored as one managed leaf record with the observed chain length; its private-key blocks are ignored.

The agent and operator CLI accept HTTPS control-plane URLs. Plain HTTP is limited to literal loopback addresses (`localhost`, `127.0.0.1`, or `::1`) for local development. This prevents bearer enrollment and operator credentials from being sent to a remote HTTP host by configuration mistake; production deployments still need TLS termination and authentication review.

For direct production serving, ATC accepts `ATC_TLS_CERT_FILE`, `ATC_TLS_KEY_FILE`, `ATC_TLS_CLIENT_CA_FILE`, and `ATC_REQUIRE_MTLS=true`. This enables TLS 1.3 and requires a verified client certificate on every connection. Agent and operator clients accept an explicit trust bundle plus client certificate/key flags (or `ATC_TLS_CA_FILE`, `ATC_CLIENT_TLS_CERT_FILE`, and `ATC_CLIENT_TLS_KEY_FILE`). Certificate identities still require authorization/RBAC mapping before a deployment should be considered multi-tenant production ready.

`ATC_OPERATOR_TOKEN` is a separate operator credential. When set, it protects operator inventory reads, findings, audit history, renewal history, and renewal/rotation requests; bootstrap enrollment remains separate. This is a single operator boundary, not role-based authorization or certificate-identity mapping.

An operator can revoke an agent credential through the confirmed agent-revocation API or CLI command. Revocation changes the stored agent status to `REVOKED`, immediately preventing further bearer-token authentication while retaining inventory and audit records for investigation.

The vulnerability-rule engine accepts reviewed JSON rules for OpenSSL version ranges through `ATC_VULNERABILITY_RULES_FILE`. It contains no current CVE list and never treats an unsupported or malformed version as safe. Rules must identify the source in their references before deployment; invalid rules prevent startup. `GET /api/v1/findings` evaluates the rules against reported asset versions at read time.

Optional alert delivery requires both `ATC_ALERT_WEBHOOK_URL` and `ATC_ALERT_WEBHOOK_SECRET`. ATC accepts only an HTTPS URL, uses TLS 1.3, signs the exact JSON body using HMAC-SHA256, and limits each delivery to ten seconds. Alert events contain public asset/certificate/job identifiers and status summaries only; keys, certificate PEM, CSRs, bearer tokens, and deployment paths are excluded. Delivery is asynchronous and a failed delivery is logged without changing a certificate or renewal state. The receiving system must verify the signature in constant time, apply timestamp and replay controls, and handle duplicate inventory-risk summaries.

Development CA material, bootstrap credentials, and bearer-agent tokens are development-only facilities. Production deployment requires secret management, mutual TLS, operator authentication/RBAC, monitoring, and independent security review.
