# Hardware Signer Plugin Contract

ATC can use a TPM, HSM, or other non-exportable key provider through an agent-local signer plugin. Configure `key_store: hardware_plugin` and an absolute `hardware_signer_plugin` path in the trusted agent YAML. ATC rejects a plugin path that is a symlink, not a regular file, or writable by group/world.

For each operation ATC starts the plugin without arguments, writes one JSON request to standard input, and expects one JSON response on standard output. Standard error is discarded so a vendor tool cannot accidentally put sensitive material in ATC logs. A response is limited to 256 KiB. The request operations are:

```json
{"operation":"generate","algorithm":"ECDSA_P256"}
{"operation":"create_csr","key_id":"pkcs11:slot-1/key-7","common_name":"api.example.test","dns_names":["api.example.test"]}
{"operation":"sign","key_id":"pkcs11:slot-1/key-7","data_base64":"..."}
{"operation":"delete","key_id":"pkcs11:slot-1/key-7"}
```

`generate` responds with `key_id` and `algorithm`. `create_csr` responds with `csr_pem`; ATC validates the CSR signature, common name, and SAN set before it goes to an issuer. `sign` responds with `signature_base64`. A successful `delete` response is `{}`.

The plugin must keep the private key and its hardware handle inside the TPM/HSM. ATC has no export operation for this key store. Consequently it supports certificate-only renewal of a preconfigured hardware key. It intentionally rejects file or Kubernetes-Secret private-key rotation for hardware-backed targets; moving a key handle or changing a TLS-service binding must be done by the platform-specific HSM/TPM deployment procedure.
