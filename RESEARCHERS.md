# For security researchers

Thank you for considering a review. This page tells you what is here, what is
not, and how to get started quickly.

## What you can review

The cryptographic protocol code that the Sentient apps and Business Terminal
run, unmodified in behaviour: the legacy-parity vectors prove byte-for-byte
equality with the deployed implementations (see [TESTING.md](TESTING.md)).

| Area | Start here | Questions worth asking |
|---|---|---|
| Consumer 1:1 messages | `src/hybrid-v1/index.ts` | Is the hybrid combiner sound? Is every routing field bound? What follows from the absence of sender authentication? |
| Business messaging | `src/business/core.js`, `conversation-keys.js` | Can a wrap or message be replayed, re-targeted or attributed to someone else? Is the commitment check complete? |
| Groups | `src/group/core.js`, `keys.js` | What can a removed member still do? Are key links and revocation checks right? |
| Calls | `src/call/handshake.ts`, `frame-web.js` | Is the transcript complete (DTLS binding, roles, nonces)? Can the handshake be downgraded or replayed? |
| Recovery | `src/recovery/*` | Are the split-knowledge claims accurate? |
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

The server-side controls (authorization, pairing rules, rate limits, device
enrollment, revocation, attestation policy), the mobile apps' platform key
storage and Sentient's infrastructure are proprietary. A review of this package
is not a review of the Sentient service, and we will not describe it as one.
