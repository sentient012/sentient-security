# Changelog

## 0.4.1

- Documentation: README, THREAT_MODEL, PROTOCOLS, RESEARCHERS, SECURITY and ROADMAP describe how Sentient 4.2.0 uses each module (one-to-one messaging, multi-device, groups, Business Terminal, calls with call keys bound to device identities, key transparency, two-key recovery and encrypted backups) and what lives in the app, Terminal and backend instead. The session protocol specification moved to `docs/session-protocols.md` and now ships in the package, with the call key binding format.
- No code or wire format changes; all tests and legacy parity vectors are unchanged.

## 0.4.0

- `session/transparency` (new): key transparency log ("sentient-kt-v0-experimental"). A Merkle tree over directory entries with RFC 9162 hashing (leaf 0x00, node 0x01); `MerkleTree` builds roots, inclusion proofs and consistency proofs for the log operator; `verifyInclusion` and `verifyConsistency` implement the RFC 9162 verification algorithms. Tree heads are signed with Ed25519 + ML-DSA-65 (`signTreeHead`, `verifyTreeHead`); `evaluateTreeHead` rejects a bad signature, rollback, equivocation, an inconsistent history, and stale or future heads. Split views are not detected without gossip or an auditor.
- No deployed wire format changes; all legacy parity vectors are unchanged.

## 0.3.0

- `session/business-roster` (new): signed, versioned organization roster for the Business Terminal ("sentient-business-roster-v0-experimental"). It lists the authorized Terminal devices and organization access keys. A change must be signed by a device listed in the previous version; rollback, equivocation, gaps, expiry and freezing are detected; an unsigned change is an identity reset. `rosterFilterState` applies the roster to a business v1 key state, so a Terminal device or organization key the server adds by itself receives no conversation key and a Terminal signing key it makes up never verifies.
- `recovery/keys` (new): Sentient recovery v2 (two 20-digit recovery keys, HKDF-derived server token and backup wrap key, account-bound backup sealing), moved unchanged from the Sentient app so there is one implementation. Byte-identical to the app and the website's WebCrypto derivation (tested).
- No deployed wire format changes; all legacy parity vectors are unchanged.

## 0.2.0

- Publishes the session protocols as `session/pqxdh`, `session/ratchet`, `session/negotiation`, `session/device-list`, `session/group-sender-keys` and `session/identity-verification`. Sentient releases at the time kept them switched off; Sentient 4.2.0 is the first to use them. No deployed wire format changes: all legacy parity vectors are unchanged.

- fixes from Sentient's internal review of 2026-11-25:
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
