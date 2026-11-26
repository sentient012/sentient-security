# For security researchers

Thank you for considering a review. This page tells you what is here, what is
not, and how to get started quickly.

## What you can review

The cryptographic protocol code that the Sentient app and Business Terminal
run. The app and Terminal import this package at an exact version; the
legacy-parity vectors prove byte-for-byte equality with the formats Sentient
has deployed (see [TESTING.md](TESTING.md)).

| Area | Start here | Questions worth asking |
|---|---|---|
| Key agreement and ratchet (Sentient 4.2.0) | `src/experimental/pqxdh.ts`, `ratchet.ts` | Do the deviations from PQXDH hold up? Is the epoch ratchet's post-compromise claim right? Can skipped keys or epoch retention be abused? |
| Device lists, identity verification, negotiation | `src/experimental/device-list.ts`, `identity-verification.ts`, `negotiation.ts` | Can a device be added, a list rolled back or forked, or a session downgraded? |
| Groups | `src/experimental/group-sender-keys.ts`, `src/group/*` | What can a removed member still do? Can a hand-off or message be attributed to someone else? |
| Business messaging and rosters | `src/business/*`, `src/experimental/business-roster.ts` | Can a wrap or message be replayed or re-targeted? Can the server get a key to an unapproved device? |
| Calls | `src/call/handshake.ts`, `frame-web.js` | Is the transcript complete (DTLS binding, roles, nonces)? Can the handshake be downgraded or replayed? |
| Key transparency | `src/experimental/transparency.ts` | Are the inclusion and consistency checks complete? What can a malicious log still do? |
| Recovery | `src/recovery/*` | Are the two-key and split-knowledge claims accurate? |
| Compatibility (Sentient 4.1.0) | `src/hybrid-v1/index.ts` | What follows from the absence of sender authentication? |
| Encodings | `src/encoding`, `src/kem` | Are there canonicalization ambiguities? |

Known limitations are listed in [THREAT_MODEL.md](THREAT_MODEL.md). A report
that shows one of them is worse than stated is valuable too.

## Getting started

```sh
git clone https://github.com/sentient012/sentient-security
cd sentient-security
npm ci
npm test
```

Node.js 20.19 or later. All tests run offline. `test/scenarios.mjs` is a
convenient harness for writing your own attack cases.

## Rules of engagement

- Test only this code, locally. Do **not** test against Sentient's production
  service or other people's accounts.
- Report privately through GitHub's private vulnerability reporting
  ([SECURITY.md](SECURITY.md)). We acknowledge reports within 5 business days.
- There is no bug bounty and no payment. We credit reporters who want credit.

## Not in this repository

The server-side controls (authorization, row-level security, pairing rules,
rate limits, device enrollment, attestation, revocation), the mobile apps' and
Terminal's key storage and Sentient's infrastructure live in Sentient's
application and backend codebases.
