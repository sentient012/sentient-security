# Changelog

## 0.2.0

- Publishes the session protocols as `session/pqxdh`, `session/ratchet`, `session/negotiation`, `session/device-list`, `session/group-sender-keys` and `session/identity-verification`. They are implemented and tested but NOT independently reviewed, and every Sentient release keeps them off by default. No deployed wire format changes: all legacy parity vectors are unchanged.

- experimental fixes from the 2026-11-25 audit (not reviewed, still off by default):
  - E-1 negotiation: default bundles sign both suite ids; either id selects the session suite.
  - E-2 downgrade: `selectProtocol({ pin })` returns `"blocked"`, never legacy, for an upgraded account; pins are per account; `clearUpgrade` after a user-visible reset.
  - E-3 prekeys: `rotateSignedPrekeys` with a grace period for retired signed prekeys, `addOneTimePrekeys`, `publicSignedPrekeys`, `buildBundle`, `signCapabilities`.
  - E-4 device lists: signed `expiresAt`, `stale` verdict, `refreshDeviceList` / `needsRefresh`, fork detection with `deviceListDigest` / `compareGossip`.
  - E-5 group sender keys: `acceptDistribution(d, from, group)` requires the authenticated session peer.
  - E-6 ratchet: 4 post-quantum receiving epochs kept (`PQ_RECV_EPOCHS_RETAINED`).
  - E-8 PQXDH: last-resort replay records bound to, and pruned with, their signed prekey.
  - Regression tests: `test/experimental-defects.test.mjs`.

## Earlier unreleased (experimental, not in the package)

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
