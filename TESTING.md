# Testing

```sh
npm ci
npm test                 # builds, then runs every test in test/
npx tsc -p tsconfig.experimental.json && node --test test/experimental-identity.test.mjs
npm run verify:pack      # builds the npm tarball and checks its file list
npm run test:packed      # installs the tarball into a temp project and runs the suite against it
```

## Legacy parity vectors

`test/vectors/legacy-vectors.json` holds the output of `test/scenarios.mjs`
run against the **deployed Sentient source**. Commits and per-file SHA-256s
are recorded in the file. `tools/capture-legacy-vectors.cjs` produced them:

- `crypto.getRandomValues` and the apps' own RNG hook are routed through one
  public, test-only deterministic stream (`src/testing`), and the clock is fixed.
- Deployed code consumes randomness in a fixed order, so identical streams give
  identical bytes only if this package is byte-compatible.

`test/legacy-parity.test.mjs` runs the same scenarios against this package
through its export map and requires deep equality. It covers hybrid-v1
envelopes, business wraps, messages, attachments, scanner and org-key boxes,
group wraps, links and messages, notification previews, recovery formats, the
call handshake (all four signed messages and the media key) and browser frame
encryption. Mutating the transcript order or the canonical encoding makes these
tests fail, which is how we check that they can fail.

The capture tool needs the private application source, so outside reviewers
cannot re-run it. The vectors themselves are public and reproducible.

## Negative tests

`test/negative.test.mjs` covers tampered ciphertexts, tags, nonces, KEM
ciphertexts, routing fields and signatures (each component), wrong recipients,
wrong epochs or groups, revoked signers, stale or retargeted call messages,
missing peer keys, malformed payloads, RNG bias (chi-square) and documented
limitations (for example, hybrid-v1 accepts a forged sender).

## Runtimes

CI runs Node.js. Browser, Hermes and JavaScriptCore runs are performed by the
consuming Sentient apps' own test and device suites. They are not part of this
repository's CI.
