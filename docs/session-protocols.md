# Sentient 4.2.0 session protocols

These are the protocols Sentient 4.2.0 uses between devices: one-to-one
messaging, multi-device, groups, Business Terminal device authorization, call
key bindings and key transparency. They are published in this package as
`@sentient012/security/session/*`; the Sentient app and Business Terminal import
them at an exact version. The source lives in `src/experimental/` and the
protocol ids end in `-v0-experimental`: these names are fixed wire identifiers
kept for compatibility, not a statement about whether the protocols are in use.

A library default (`EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT = false`) means that
nothing is switched on merely by installing the package; Sentient 4.2.0 enables
the session protocols explicitly. Sentient 4.2.0 keeps `sentient-hybrid-v1` only
for devices still on Sentient 4.1.0, and never falls back to it for an account
that has used the session protocol (`session/negotiation`).

| Module | Protocol id | Purpose |
|---|---|---|
| `pqxdh.ts` | `sentient-pqxdh-v0-experimental` | Authenticated initial key agreement (PQXDH structure) |
| `ratchet.ts` | `sentient-tr-v0-experimental` | Double Ratchet + sparse ML-KEM epoch ratchet (Triple-Ratchet structure) |
| `device-list.ts` | `sentient-device-list-v0-experimental` | Signed, versioned per-account device lists |
| `group-sender-keys.ts` | `sentient-group-sk-v0-experimental` | Per-sender ratcheted group messaging |
| `identity-verification.ts` | `sentient-identity-fingerprint-v0` | Comparison codes, key-change detection, QR-bound verification |
| `negotiation.ts` | none | Protocol selection and downgrade rules |
| `business-roster.ts` | `sentient-business-roster-v0-experimental` | Signed organization rosters for the Business Terminal |
| `transparency.ts` | `sentient-kt-v0-experimental` | Key transparency log (RFC 9162 Merkle tree, signed tree heads) |
| (app and Terminal) | `sentient-call-key-binding-v0-experimental` | A device's session identity vouching for its call signing key |

## Sources and licensing

- Signal's *Double Ratchet* (rev. 4, 2025-11-04, including SPQR and the Triple
  Ratchet), *PQXDH* (rev. 3, 2023-05-24) and *X3DH* specifications. Each
  states: "This document is hereby placed in the public domain."
- No code from libsignal (AGPL-3.0) was consulted, copied or translated.
  The implementation follows the specifications' pseudocode and uses
  MIT-licensed `@noble/*` primitives only.
- Patents: we know of no patent asserted against these specifications; no
  professional patent search has been done.

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
| Server substituting a whole identity or adding a device | Refused when it changes a pinned identity or adds a device the signed device list does not name; on first contact, the key must be in the transparency log (the owner's devices can see it); verification by safety number closes trust on first use |
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

## 5a. Fixes made before activation

Integration defects found by Sentient's own review in November 2026. Each has a
regression test in `test/experimental-defects.test.mjs`.

| Id | Defect | Fix |
|---|---|---|
| E-1 | Default bundles signed only the key-agreement id, so the selector always chose legacy | Default capabilities list both suite ids; either id selects the suite |
| E-2 | An upgraded sender fell back to hybrid-v1 when the server withheld the peer's bundle | `selectProtocol({ pin })` returns `"blocked"`; pins are per account; `clearUpgrade` only after a user-visible reset |
| E-3 | Rotating the signed prekey broke initial messages in flight | `rotateSignedPrekeys` keeps retired prekeys for a grace period (14 days by default); `addOneTimePrekeys` for replenishment |
| E-4 | A frozen or forked device list went undetected | Signed `expiresAt` (30 days), `stale` verdict, `refreshDeviceList`, and `deviceListDigest` / `compareGossip` for fork detection between peers. This is **not** key transparency |
| E-5 | A sender-key hand-off was accepted for any claimed sender | `acceptDistribution(d, from, group)` requires the authenticated session peer |
| E-6 | A message delayed across two PQ epochs was lost | Four PQ receiving epochs are kept |
| E-8 | Last-resort replay records were evicted by count | Records are bound to, and pruned with, their signed prekey |

## 6. Open research items

1. A formal model, for example ProVerif or Tamarin, of pqxdh + the epoch
   ratchet.
2. Interoperability vectors from a second, independent implementation.
3. Performance on low-end Android (the figures above are desktop figures).

## Business Terminal organization roster (`sentient-business-roster-v0-experimental`, 0.3.0)

Business v1 lets the server choose who must be able to read a business conversation (the organization's Terminal devices and its organization access key) and which Terminal signing keys are genuine. The roster moves that decision to the organization's own devices:

- **Statement:** `{ v, organizationId, version, devices[], orgKeys[], issuedAt, expiresAt, signerKeyId, signature }`, signed with Ed25519 + ML-DSA-65; both must verify. Each device lists its key id, business user, signing keys and encryption keys.
- **Versions:** version n + 1 must be signed by a device listed in version n with the same signing keys. Gaps are rejected; walk the chain with `evaluateRosterChain`.
- **Detection:** a lower version is `stale`, the same version with different content is `equivocation`, and an expired roster is `frozen` or `expired`. A roster signed only by a device the pinned roster does not list is an `identity_reset` and must be shown to the user, never accepted silently.
- **Applying it:** `rosterFilterState(state, current, history)` keeps only these:
  - Terminal recipients and organization access keys listed in the current roster with the same encryption keys;
  - Terminal signing keys listed with the same signing keys in any accepted version, so a former employee's messages stay verifiable.

  Customer devices pass unchanged.
- **Transparency:** every roster version is in the key transparency log; Terminals and phones follow a new version only with proof it is logged.
- **Not provided:** real-world identity of the organization (Sentient's business verification establishes that, outside cryptography).

## Key transparency log (`sentient-kt-v0-experimental`, 0.4.0)

The directory server can show a client a key that was never published by its owner. The log makes every key a client relies on public and append-only:

- **Entries:** each published device identity, signed device list, business roster and call key binding is one entry, an exact UTF-8 string chosen by the log. Leaf = SHA-256(0x00 || entry); node = SHA-256(0x01 || left || right) (RFC 9162).
- **Tree heads:** `{ v, logId, size, root, timestamp }`, signed with Ed25519 + ML-DSA-65 (both must verify) under a log key clients pin.
- **Clients:** require an inclusion proof for a key before trusting it; check each new head against the last one with a consistency proof (`evaluateTreeHead`: rollback, equivocation, inconsistency, stale and future heads are rejected); and monitor their own account's entries, so a key published for them by someone else is noticed by their own devices.
- **Not provided:** detection of a split view (separate consistent logs per client) without tree-head gossip between clients or an independent auditor; directory privacy (entries name accounts, as the directory does); any protection before a client first pins a head.

## Call key bindings (`sentient-call-key-binding-v0-experimental`)

Calls use `sentient-call-hybrid-v1` (see [PROTOCOLS.md](../PROTOCOLS.md)), which
authenticates each side with a per-device call signing key. In Sentient 4.2.0
each device's **session identity** vouches for that key:

- **Statement:** `{ v, userId, deviceId, callKeyId, ed25519_public_key, ml_dsa_public_key, issuedAt }`,
  signed with the session identity's Ed25519 + ML-DSA-65 keys (business framing,
  context = the protocol id); both signatures must verify. It is stored with the
  call key and appended to the transparency log.
- **Consumer calls:** each phone checks the other phone's key against that
  device's pinned identity and the account's signed device list.
- **Business calls:** the phone checks the Terminal's key against the
  organization's roster; the Terminal checks the customer's key against the
  customer device's pinned identity and signed device list (pins kept per
  organization in the browser), with first trust proven in the transparency log.
- **Verdicts:** verified; unbound (an older app that never presented a binding:
  encrypted, never shown as a verified device); mismatch (fails the handshake;
  includes a binding that disappears after one was seen); unavailable (the
  directory could not be reached: not verified this time). A device change or
  account recovery needs explicit trust before the next call verifies.
