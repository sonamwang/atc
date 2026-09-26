# Initial Threat Model

| Threat | MVP control | Residual risk |
|---|---|---|
| Private-key disclosure | The scanner accepts only certificate PEM blocks; API models and logs have no key fields. | A compromised local host can still read its own keys. |
| Unauthorized enrollment | Registration requires a configured bootstrap credential and compares it in constant time. | Bootstrap token rotation and mTLS are not yet implemented. |
| Cross-agent inventory write | The server resolves agent identity from the bearer token and derives asset ownership server-side. | The in-memory store is single-process only. |
| Command injection | OpenSSL is invoked with fixed executable and arguments; no shell is used. | Local PATH resolution remains a deployment concern. |
| Malicious or oversized certificate input | File scan does not follow symlinks and rejects files over 10 MiB; JSON body is capped at 2 MiB. | Parser fuzzing and content-type policy remain future work. |
| Server or database compromise | Agent and named-operator tokens are retained as hashes; audit records have no normal mutation API. | Encryption at rest and immutable/WORM audit storage remain deployment work. |
