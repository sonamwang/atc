# Contributing

Keep security-sensitive changes small, tested, and documented. Run `make test vet build` before submitting a change. New API fields must be reviewed to ensure they cannot carry private-key material or credentials.

Do not add shell execution with untrusted input. Use explicit executable arguments and bounded contexts for external commands.
