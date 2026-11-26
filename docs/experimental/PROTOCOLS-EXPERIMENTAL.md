# Session protocols (NOT active for users, NOT reviewed)

**Status: implemented in source and tested; published in the npm package as
`@sentient012/security/session/*` since 0.2.0; NOT independently reviewed; off
by default in every Sentient release** (`EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT
= false`). The source lives in `src/experimental/`. Sentient's server already
hosts the public key directory these protocols need (identities, signed and
one-time prekeys, signed device lists), and nothing uses it until a release
turns the protocols on. Cryptographers are invited to review it **before**
activation.

| Module | Protocol id | Purpose |
|---|---|---|
| `pqxdh.ts` | `sentient-pqxdh-v0-experimental` | Authenticated initial key agreement (PQXDH structure) |
| `ratchet.ts` | `sentient-tr-v0-experimental` | Double Ratchet + sparse ML-KEM epoch ratchet (Triple-Ratchet structure) |
| `device-list.ts` | `sentient-device-list-v0-experimental` | Signed, versioned per-account device lists |
| `group-sender-keys.ts` | `sentient-group-sk-v0-experimental` | Per-sender ratcheted group messaging |
| `identity-verification.ts` | `sentient-identity-fingerprint-v0` | Comparison codes, key-change detection, QR-bound verification |
| `negotiation.ts` | none | Protocol selection and downgrade rules |

## Sources and licensing

- Signal's *Double Ratchet* (rev. 4, 2025-11-04, including SPQR and the Triple
  Ratchet), *PQXDH* (rev. 3, 2023-05-24) and *X3DH* specifications. Each
  states: "This document is hereby placed in the public domain."
- No code from libsignal (AGPL-3.0) was consulted, copied or translated.
  The implementation follows the specifications' pseudocode and uses
  MIT-licensed `@noble/*` primitives only.
- Patents: we know of no patent asserted against these specifications, but we
  have not done a professional patent search. That must happen before any
  production use.

## 1. Key agreement (sentient-pqxdh-v0)

Per device: a hybrid signing identity (Ed25519 + ML-DSA-65), an X25519 DH
identity key IK bound to it by a hybrid signature, a signed X25519 prekey SPK,
a signed last-resort ML-KEM-768 prekey PQSPK, and one-time X25519 and ML-KEM
prekeys. The bundle also carries a signed list of supported protocols.

```
DH1 = X25519(IK_A, SPK_B)   DH2 = X25519(EK_A, IK_B)   DH3 = X25519(EK_A, SPK_B)
DH4 = X25519(EK_A, OPK_B)   if a one-time prekey was used
(CT, SS) = ML-KEM-768.Encaps(PQOPK_B or PQSPK_B)
SK = HKDF-SHA-256(salt = 0^32, ikm = 0xFF^32 || DH1 || DH2 || DH3 [|| DH4] || SS,
                  info = "Sentient_CURVE25519_SHA-256_MLKEM768_PQXDH-v0", L = 64)
SK_ec = SK[0..32)   SK_pq = SK[32..64)
AD = canonical({ v, initiator: {userId, deviceId, ik, ed, mldsa}, responder: {...} })
```

Deviations from PQXDH (deliberate):
1. Prekeys are signed with the hybrid Ed25519 + ML-DSA-65 identity, not XEdDSA.
2. The initiator signs the initial message (authentication against a future
   quantum adversary; costs deniability).
3. The AD binds full identities and the protocol id.

Replay: one-time prekeys are deleted on use. When only last-resort prekeys
were used, the responder remembers a hash of the accepted initial message
(the 10,000 most recent).

## 2. Session (sentient-tr-v0)

- **Double Ratchet** as in the specification (section 3), with
  `KDF_RK = HKDF(salt = RK, ikm = DH, info = "<id>:dr-root", 64)` and
  `KDF_CK = HMAC-SHA-256(CK, 0x01 / 0x02)`. MAX_SKIP = 1000 per chain, at most
  2000 stored skipped keys (oldest evicted).
- **Post-quantum epochs.** Epoch 0's root is `HKDF(SK_pq, "...Chain Start")`.
  Epochs alternate between the parties: the initiator proposes odd epochs, the
  responder even ones. The proposer attaches a fresh ML-KEM-768 encapsulation
  key to its messages. The peer encapsulates, derives
  `root' = HKDF(salt = root, ikm = SS, "...Chain Add Epoch")`, moves to the new
  epoch and attaches the ciphertext until it sees the proposer use the new
  epoch. Each epoch derives one chain per direction. Only the current and the
  previous epoch's receiving chains are kept. A proposal is made at most once
  per `interval` messages (default 20).
- **Message key** = `HKDF(salt = pq_mk, ikm = ec_mk, info = "<id>:hybrid-message-key", 32)`
  (specification 7.2, KDF_HYBRID). AEAD = XChaCha20-Poly1305 with the key and
  nonce from `HKDF(mk, "<id>:aead", 56)`, and AD = session AD || canonical(header).

### State machine summary

| Event | Effect |
|---|---|
| encrypt | Step the sending chain and the PQ sending chain. Maybe propose the next epoch. Attach a pending ciphertext. |
| decrypt, new DH key | Store skipped keys of the old chain (up to `pn`), then perform the DH ratchet step |
| decrypt, ciphertext for our proposal | Decapsulate, advance the epoch, delete the decapsulation key |
| decrypt, proposal from the peer (their turn) | Encapsulate, advance the epoch, attach the answer |
| any failure | Throw. The input state is never modified (functions are pure). |

Callers must persist the returned state **before** acting on the result, and
must serialize operations per session (`SessionMutex`).

## 3. Threat model and claimed properties

| Adversary | Claimed |
|---|---|
| Network attacker, honest server | Confidentiality, integrity, sender-device authentication |
| Server substituting prekeys | Detected (hybrid prekey signatures) |
| Server substituting a whole identity or adding a device | Detected only with identity verification or pinned device lists. Silent on first contact (trust on first use) |
| Classical: state stolen at time t | Messages before t stay secret (FS). After both parties ratchet once, new messages are secret again (PCS) |
| Quantum, recording now | Session keys need the ML-KEM secret (SK includes SS). Each message key needs the PQ chain |
| Quantum: state stolen at time t | PQ FS and PCS at epoch granularity (after the next completed epoch) |
| Malicious group member | Cannot forge another member's group messages (hybrid signatures) |

**Not provided:** deniability (signatures), metadata protection, protection
against a compromised device while it remains compromised, header encryption,
secure deletion (JavaScript strings cannot be wiped), and protection of
backups that contain session state.

## 4. Multi-device (device-list.ts)

A device list is signed by a device that was in the previous version, and
versions only increase. Peers pin the list and classify each new one as
unchanged / changed (added and removed devices) / identity reset / rejected
(rollback, equivocation, a key changed under the same device id). Account
recovery without any old device produces an identity reset. That reset is
surfaced to the user, never accepted silently.

## 5. Groups (group-sender-keys.ts) and MLS

Per-sender chains give forward secrecy within an epoch and hybrid-signed
messages. Membership changes still rely on new epochs (sender chains are
re-distributed over pairwise sessions). MLS (RFC 9420) would add efficient
post-compromise security for large groups and agreed group state. We did not
adopt it here: no maintained, reviewed, permissively licensed TypeScript MLS
implementation with post-quantum ciphersuites was available to us. Checking
the current options is the first step of any group redesign.

## Performance (desktop only: win32 x64 node v24.19.0; NOT a phone)

Measured with `node tools/bench-experimental.mjs` (rekey interval 20, 200 alternating 100-byte messages):

| Metric | Value |
|---|---|
| pqxdh initiate / respond | 84.9 ms / 51.9 ms |
| Initial message size | 13861 bytes (ML-DSA keys and signatures dominate) |
| Ratchet encrypt / decrypt (average) | 0.57 ms / 4.46 ms |
| Message size average / min / max | 424 / 346 / 1954 bytes |
| Share of messages carrying ML-KEM material | 0.05 |
| Serialized session state | 8171 bytes |
| Deployed hybrid-v1, one device envelope | 5.9 ms, 1976 bytes |

Low-end Android (Hermes, no JIT for some paths) is expected to be several times slower. It has not been measured.

## 5a. Fixes after the 2026-11-25 internal audit

These were integration defects found by Sentient's own audit, not by an
independent reviewer. Each has a regression test in
`test/experimental-defects.test.mjs`.

| Id | Defect | Fix |
|---|---|---|
| E-1 | Default bundles signed only the key-agreement id, so the selector always chose legacy | Default capabilities list both suite ids; either id selects the suite |
| E-2 | An upgraded sender fell back to hybrid-v1 when the server withheld the peer's bundle | `selectProtocol({ pin })` returns `"blocked"`; pins are per account; `clearUpgrade` only after a user-visible reset |
| E-3 | Rotating the signed prekey broke initial messages in flight | `rotateSignedPrekeys` keeps retired prekeys for a grace period (14 days by default); `addOneTimePrekeys` for replenishment |
| E-4 | A frozen or forked device list went undetected | Signed `expiresAt` (30 days), `stale` verdict, `refreshDeviceList`, and `deviceListDigest` / `compareGossip` for fork detection between peers. This is **not** key transparency |
| E-5 | A sender-key hand-off was accepted for any claimed sender | `acceptDistribution(d, from, group)` requires the authenticated session peer |
| E-6 | A message delayed across two PQ epochs was lost | Four PQ receiving epochs are kept |
| E-8 | Last-resort replay records were evicted by count | Records are bound to, and pruned with, their signed prekey |

## 6. Validation still required before ANY production use

1. Independent cryptographic review of all modules.
2. A formal model, for example ProVerif or Tamarin, of pqxdh + the epoch
   ratchet. **None has been done.**
3. Interoperability vectors from a second, independent implementation.
4. Real-device performance on low-end Android (only desktop figures exist).
5. A product design for key-change warnings and identity resets.
6. A patent and licensing review.

## Business Terminal organization roster (`sentient-business-roster-v0-experimental`, 0.3.0)

Business v1 lets the server choose who must be able to read a business conversation (the organization's Terminal devices and its organization access key) and which Terminal signing keys are genuine. The roster moves that decision to the organization's own devices:

- **Statement:** `{ v, organizationId, version, devices[], orgKeys[], issuedAt, expiresAt, signerKeyId, signature }`, signed with Ed25519 + ML-DSA-65; both must verify. Each device lists its key id, business user, signing keys and encryption keys.
- **Versions:** version n + 1 must be signed by a device listed in version n with the same signing keys. Gaps are rejected; walk the chain with `evaluateRosterChain`.
- **Detection:** a lower version is `stale`, the same version with different content is `equivocation`, and an expired roster is `frozen` or `expired`. A roster signed only by a device the pinned roster does not list is an `identity_reset` and must be shown to the user, never accepted silently.
- **Applying it:** `rosterFilterState(state, current, history)` keeps only these:
  - Terminal recipients and organization access keys listed in the current roster with the same encryption keys;
  - Terminal signing keys listed with the same signing keys in any accepted version, so a former employee's messages stay verifiable.

  Customer devices pass unchanged.
- **Not provided:** key transparency (equivocation towards people who never compare rosters), and real-world identity of the organization.
