# Contributing

Thank you for reviewing or improving this code.

- **Security issues**: follow [SECURITY.md](SECURITY.md) and do not open public issues.
- **Wire compatibility is a hard rule.** Deployed protocols must stay
  byte-compatible. A change that alters any legacy-parity vector will not be
  merged. New behaviour needs a new protocol identifier and its own vectors.
- No new cryptographic primitives. Use maintained, reviewed libraries.
- Every change needs tests: positive, negative and, for protocol code, vectors.
- Do not submit code copied or translated from GPL/AGPL-licensed projects
  (including libsignal). This project is Apache-2.0.
- By contributing you agree that your contribution is licensed under Apache-2.0.
