# Changelog

## Unreleased (experimental, not in the package)

- src/experimental: sentient-pqxdh-v0, sentient-tr-v0 (Double Ratchet + sparse ML-KEM epoch ratchet), signed device lists, group sender keys, protocol negotiation, QR-bound identity verification; 22 tests; docs/experimental/PROTOCOLS-EXPERIMENTAL.md.

## 0.1.0 (unreleased)

First extraction of Sentient's deployed protocol code. Wire formats unchanged and verified byte for byte against vectors captured from the deployed source.

- `hybrid-v1`: strict-TypeScript port; `classifyPayload` distinguishes absent, malformed and unknown-version payloads.
- `business`, `group`: moved unchanged; the duplicated hybrid seal now lives once in `kem`.
- Revocation checks for business and group wraps and key links prefer the server-recorded time over the signer-claimed time when the server provides it (stricter only).
- `call`: handshake with storage and network removed (seeds and key lookups injected); one canonical encoding module.
- `notification-preview`: uses `hybrid-v1` instead of a second copy of its decryption.
- `hybrid-v1`: consumer attachment format (`attachmentAad`, `sealAttachment`, `openAttachment`) with an optional AEAD hook for native fast paths.
- `call`: optional `expectPeer` binding check (from the Business Terminal), injectable `random` and `now`, assignable `onSecurityState`; the phone and terminal handshakes were shown byte-identical and are now one class.
- `random`: CSPRNG, unbiased PINs, tokens and ids.
- `testing`: deterministic stream for vectors (test only).
