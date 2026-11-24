/*
 * Negative and property tests: tampering, wrong context, wrong recipient,
 * malformed input, revoked keys, randomness requirements.
 */
import test from "node:test";
import assert from "node:assert/strict";

import { x25519 } from "@noble/curves/ed25519.js";
import { base64 } from "@scure/base";

import * as H from "@sentient012/security/hybrid-v1";
import * as B from "@sentient012/security/business";
import * as G from "@sentient012/security/group";
import { createSigningDirectory } from "@sentient012/security/group/keys";
import * as R from "@sentient012/security/random";
import { canonicalize, canonicalizeCallV1, utf8Decode, constantTimeEqual } from "@sentient012/security/encoding";
import * as C from "@sentient012/security/call";
import { deterministicRandom } from "@sentient012/security/testing";

const b64 = (u) => base64.encode(u);
function flip(text, index = 5) {
  const bytes = base64.decode(text);
  bytes[Math.min(index, bytes.length - 1)] ^= 1;
  return b64(bytes);
}

function device(userId, credentialId) {
  const secrets = H.newDeviceSecrets();
  const keys = H.deviceKeysFromSecrets(secrets.x25519PrivateKey, secrets.mlKemSeed);
  return {
    secrets,
    keys,
    priv: { deviceKeyId: H.deviceKeyIdFor(credentialId), x25519PrivateKey: secrets.x25519PrivateKey, mlKemSecretKey: keys.mlKemSecretKey },
    bundle: { id: H.deviceKeyIdFor(credentialId), user_id: userId, credential_id: credentialId, x25519_public_key: b64(keys.x25519PublicKey), ml_kem_public_key: b64(keys.mlKemPublicKey) },
  };
}

const A = "a-user", Bo = "b-user";
const alice = device(A, "ca"), bob = device(Bo, "cb"), eve = device("e-user", "ce");
const payload = H.encryptPayload({ plaintext: "secret", threadId: "t1", senderUserId: A, receiverUserId: Bo, recipients: [alice.bundle, bob.bundle] });
const bobEnv = payload.envelopes[1];

test("hybrid-v1: round trip for each recipient", () => {
  assert.equal(H.decryptEnvelope(payload, payload.envelopes[0], alice.priv), "secret");
  assert.equal(H.decryptEnvelope(payload, bobEnv, bob.priv), "secret");
});

test("hybrid-v1: every authenticated field is bound (tamper -> reject)", () => {
  const cases = {
    ciphertext: { ...bobEnv, ciphertext: flip(bobEnv.ciphertext) },
    tag: { ...bobEnv, ciphertext: flip(bobEnv.ciphertext, 10_000) },
    nonce: { ...bobEnv, nonce: flip(bobEnv.nonce) },
    ephemeral: { ...bobEnv, ephemeralX25519PublicKey: b64(x25519.getPublicKey(x25519.utils.randomSecretKey())) },
    kemCiphertext: { ...bobEnv, mlKemCiphertext: flip(bobEnv.mlKemCiphertext) },
    deviceKeyId: { ...bobEnv, deviceKeyId: "other:hybrid-v1" },
    userId: { ...bobEnv, userId: "someone" },
    credentialId: { ...bobEnv, credentialId: "other" },
  };
  for (const [name, env] of Object.entries(cases)) assert.throws(() => H.decryptEnvelope(payload, env, bob.priv), undefined, name);
  for (const field of ["threadId", "senderUserId", "receiverUserId"]) {
    assert.throws(() => H.decryptEnvelope({ ...payload, [field]: "x" }, bobEnv, bob.priv), undefined, field);
  }
});

test("hybrid-v1: wrong recipient key cannot open", () => {
  assert.throws(() => H.decryptEnvelope(payload, bobEnv, eve.priv));
  assert.throws(() => H.decryptEnvelope(payload, bobEnv, alice.priv));
});

test("hybrid-v1 LIMITATION (documented): no sender authentication - anyone with the recipient's public keys can claim any sender", () => {
  // Eve forges a message "from Alice" to Bob. It decrypts. This is the deployed
  // protocol's property; the backend insert policy is the only sender check.
  const forged = H.encryptPayload({ plaintext: "forged", threadId: "t1", senderUserId: A, receiverUserId: Bo, recipients: [bob.bundle] });
  assert.equal(H.decryptEnvelope(forged, forged.envelopes[0], bob.priv), "forged");
});

test("hybrid-v1: fresh randomness per envelope (no nonce or ephemeral reuse)", () => {
  const p = H.encryptPayload({ plaintext: "x", threadId: "t", senderUserId: A, receiverUserId: Bo, recipients: [bob.bundle, bob.bundle, bob.bundle] });
  assert.equal(new Set(p.envelopes.map((e) => e.nonce)).size, 3);
  assert.equal(new Set(p.envelopes.map((e) => e.ephemeralX25519PublicKey)).size, 3);
});

test("hybrid-v1: classifyPayload distinguishes absent, malformed, unknown version and valid", () => {
  assert.deepEqual(H.classifyPayload(null), { kind: "absent" });
  assert.deepEqual(H.classifyPayload(""), { kind: "absent" });
  assert.equal(H.classifyPayload("{not json").kind, "malformed");
  assert.equal(H.classifyPayload([]).kind, "malformed");
  assert.equal(H.classifyPayload({ version: "sentient-hybrid-v2" }).kind, "unknown_version");
  assert.equal(H.classifyPayload({ ...payload, envelopes: [] }).kind, "malformed");
  assert.equal(H.classifyPayload({ ...payload, envelopes: [{ ...bobEnv, nonce: 5 }] }).kind, "malformed");
  assert.equal(H.classifyPayload({ ...payload, threadId: "" }).kind, "malformed");
  assert.equal(H.classifyPayload(payload).kind, "hybrid-v1");
  assert.equal(H.classifyPayload(JSON.stringify(payload)).kind, "hybrid-v1");
});

test("hybrid-v1: transcript property order is frozen", () => {
  const t = new TextDecoder().decode(H.buildTranscript({ threadId: "T", senderUserId: "S", receiverUserId: "R", deviceKeyId: "D", userId: "U", credentialId: "C", ephemeralX25519PublicKey: "E", mlKemCiphertext: "K" }));
  assert.equal(t, '{"version":"sentient-hybrid-v1","algorithm":"X25519+ML-KEM-768/XChaCha20-Poly1305","threadId":"T","senderUserId":"S","receiverUserId":"R","deviceKeyId":"D","userId":"U","credentialId":"C","ephemeralX25519PublicKey":"E","mlKemCiphertext":"K"}');
});

test("hybrid-v1: invalid secret lengths are rejected", () => {
  assert.throws(() => H.deviceKeysFromSecrets(new Uint8Array(31), new Uint8Array(64)), /x25519_length/);
  assert.throws(() => H.deviceKeysFromSecrets(new Uint8Array(32), new Uint8Array(32)), /mlkem_seed_length/);
});

// --- business / group ------------------------------------------------------
function bizDevice(kind, keyId) {
  const seeds = B.newDeviceSeeds();
  const signing = B.signingKeysFromSeeds(seeds);
  const kem = B.kemKeysFromSeeds(seeds);
  return { kind, keyId, signing, kem, pub: { ed25519_public_key: b64(signing.ed25519PublicKey), ml_dsa_public_key: b64(signing.mlDsaPublicKey) }, target: { kind, keyId, x25519PublicKey: kem.x25519PublicKey, mlKemPublicKey: kem.mlKemPublicKey } };
}

test("business: wrap substitution, wrong signer, wrong routing and message replay are rejected", () => {
  const phone = bizDevice("consumer_device", "p1"), term = bizDevice("terminal_device", "t1"), rogue = bizDevice("terminal_device", "t2");
  const ck = B.newConversationKey();
  const base = { interactionId: "i1", organizationId: "o1", epoch: 1, createdAt: new Date().toISOString() };
  const wrap = B.wrapConversationKey({ ...base, conversationKey: ck, recipient: phone.target, wrapper: { kind: "terminal_device", keyId: "t1", signingKeys: term.signing } });
  const expected = { interactionId: "i1", organizationId: "o1", epoch: 1 };
  assert.ok(B.unwrapConversationKey({ wrap, recipientPrivate: phone.kem, expected, wrapperPublicKeys: term.pub }));
  assert.throws(() => B.unwrapConversationKey({ wrap, recipientPrivate: phone.kem, expected, wrapperPublicKeys: rogue.pub }), /signed/);
  assert.throws(() => B.unwrapConversationKey({ wrap, recipientPrivate: phone.kem, expected: { ...expected, epoch: 2 }, wrapperPublicKeys: term.pub }), /epoch/);
  assert.throws(() => B.unwrapConversationKey({ wrap: { ...wrap, commitment: "AAAA" }, recipientPrivate: phone.kem, expected, wrapperPublicKeys: term.pub }));
  assert.throws(() => B.unwrapConversationKey({ wrap, recipientPrivate: rogue.kem, expected, wrapperPublicKeys: term.pub }), /Key encapsulation|authentication/);
  // A server that substitutes its own key, signed by a key it registered, is
  // caught only if that key is not in the directory: documented limitation.
  const header = { interactionId: "i1", organizationId: "o1", epoch: 1, messageId: "m1", senderType: "business", senderKind: "terminal_device", senderKeyId: "t1", senderId: "agent", createdAt: base.createdAt };
  const msg = B.encryptBusinessMessage({ conversationKey: ck, header, content: { kind: "text", text: "hi" }, signingKeys: term.signing });
  assert.throws(() => B.decryptBusinessMessage({ payload: msg, conversationKey: ck, senderPublicKeys: term.pub, expected: { messageId: "m2" } }), /messageId/);
  assert.throws(() => B.decryptBusinessMessage({ payload: { ...msg, ciphertext: flip(msg.ciphertext) }, conversationKey: ck, senderPublicKeys: term.pub }), /signature/);
  assert.throws(() => B.decryptBusinessMessage({ payload: { ...msg, signature: { ...msg.signature, mlDsa: flip(msg.signature.mlDsa) } }, conversationKey: ck, senderPublicKeys: term.pub }), /signature/);
  assert.throws(() => B.decryptBusinessMessage({ payload: { ...msg, signature: { ...msg.signature, ed25519: flip(msg.signature.ed25519) } }, conversationKey: ck, senderPublicKeys: term.pub }), /signature/);
  assert.throws(() => B.decryptBusinessMessage({ payload: { ...msg, v: "sentient-business-msg-v0" }, conversationKey: ck, senderPublicKeys: term.pub }), /message_version/);
  assert.throws(() => B.decryptBusinessMessage({ payload: { ...msg, suite: "weaker" }, conversationKey: ck, senderPublicKeys: term.pub }), /message_suite/);
});

test("group: wrong epoch, wrong group, revoked signer (server time) and tampered link are rejected", async () => {
  const alice = bizDevice("member", "ka"), bob = bizDevice("member", "kb");
  const gk = G.newGroupKey(), gk2 = G.newGroupKey();
  const createdAt = "2026-11-20T00:00:00.000Z";
  const msg = G.encryptGroupMessage({ groupKey: gk, header: { groupId: "g", epoch: 1, messageId: "m", senderId: "A", senderKeyId: "ka", createdAt }, content: { kind: "text", text: "x" }, signingKeys: alice.signing });
  assert.throws(() => G.decryptGroupMessage({ payload: msg, groupKey: gk, senderPublicKeys: alice.pub, expected: { epoch: 2 } }), /epoch/);
  assert.throws(() => G.decryptGroupMessage({ payload: msg, groupKey: gk, senderPublicKeys: alice.pub, expected: { groupId: "h" } }), /groupId/);
  assert.throws(() => G.decryptGroupMessage({ payload: msg, groupKey: gk2, senderPublicKeys: alice.pub }), /authentication/);
  assert.throws(() => G.decryptGroupMessage({ payload: msg, groupKey: gk, senderPublicKeys: bob.pub }), /signature/);
  const link = G.sealKeyLink({ olderKey: gk, newerKey: gk2, groupId: "g", olderEpoch: 1, wrapper: { userId: "A", keyId: "ka", signingKeys: alice.signing }, createdAt });
  assert.throws(() => G.openKeyLink({ link: { ...link, sealed: flip(link.sealed) }, newerKey: gk2, expected: {}, wrapperPublicKeys: alice.pub }), /signed/);
  assert.throws(() => G.openKeyLink({ link, newerKey: gk2, expected: {}, wrapperPublicKeys: alice.pub, expectedCommitment: "nope" }), /commitment/);
  // Revocation lookup: the server-recorded time is honoured even when the signer backdates.
  const dir = createSigningDirectory({ getSigningKeys: async () => [{ key_id: "ka", user_id: "A", ...alice.pub, revoked_at: "2026-11-21T00:00:00.000Z" }] });
  await dir.ensure(["ka"]);
  assert.ok(dir.lookup("ka", "2026-11-20T00:00:00.000Z"), "before revocation");
  assert.equal(dir.lookup("ka", "2026-11-22T00:00:00.000Z"), null, "after revocation");
  const { trustedTime } = await import("../dist/internal/time.js");
  assert.equal(trustedTime("2026-11-22T00:00:00.000Z", "2026-11-01T00:00:00.000Z"), "2026-11-22T00:00:00.000Z", "backdated claim loses to server time");
  assert.equal(trustedTime("2026-11-01T00:00:00.000Z", "2026-11-22T00:00:00.000Z"), "2026-11-22T00:00:00.000Z", "the later (stricter) time wins");
  assert.equal(trustedTime(undefined, "2026-11-01T00:00:00.000Z"), "2026-11-01T00:00:00.000Z", "old backends: deployed behaviour");
  assert.equal(dir.lookup("ka", trustedTime("2026-11-22T00:00:00.000Z", "2026-11-01T00:00:00.000Z")), null);
});

// --- call ------------------------------------------------------------------
test("call: tampered hello and stale/replayed messages fail verification, never downgrade silently", async () => {
  const id = (c) => C.signingIdentityFromSeeds(c, ...Object.values(C.newSigningSeeds()));
  const ia = id("ca"), ib = id("cb");
  const bundles = new Map([[ia.deviceKeyId, { id: ia.deviceKeyId, ed25519_public_key: b64(ia.ed25519PublicKey), ml_dsa_public_key: b64(ia.mlDsaPublicKey), is_active: true, attestation_verified: false }], [ib.deviceKeyId, { id: ib.deviceKeyId, ed25519_public_key: b64(ib.ed25519PublicKey), ml_dsa_public_key: b64(ib.mlDsaPublicKey), is_active: true, attestation_verified: false }]]);
  const mk = (role, identity) => new C.CallPqcHandshake({ role, callId: "c", callerUserId: "A", calleeUserId: "B", localIdentity: identity, getPeerBundle: async (k) => bundles.get(k) ?? null, localDtlsFingerprints: () => ["sha-256:aa"] });
  const caller = mk("caller", ia), callee = mk("callee", ib);
  const hello = await caller.buildHello();
  assert.equal(await callee.handleHelloBuildAccept({ ...hello, callId: "other" }), null);
  assert.equal(callee.state.state, "verification_failed");
  const callee2 = mk("callee", ib);
  assert.equal(await callee2.handleHelloBuildAccept({ ...hello, createdAt: "2020-01-01T00:00:00.000Z" }), null);
  const callee3 = mk("callee", ib);
  bundles.delete(ia.deviceKeyId);
  assert.equal(await callee3.handleHelloBuildAccept(hello), null);
  assert.equal(callee3.state.state, "unsupported", "a missing peer bundle is reported, not hidden");
});

test("canonical forms: business and call framings differ exactly where documented", () => {
  assert.equal(canonicalize({ b: 1, a: undefined }), '{"b":1}');
  assert.equal(canonicalizeCallV1({ b: 1, a: undefined }), '{"a":null,"b":1}');
  assert.throws(() => canonicalize({ x: Infinity }));
  assert.equal(canonicalizeCallV1({ x: Infinity }), '{"x":null}');
});

test("encoding: constant-time compare and UTF-8 decode modes", () => {
  assert.equal(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
  assert.equal(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3])), false);
  assert.equal(utf8Decode(new Uint8Array([0xff])), "�");
  assert.throws(() => utf8Decode(new Uint8Array([0xff]), { fatal: true }));
});

// --- random ----------------------------------------------------------------
test("random: PINs and tokens have the right shape and come from the CSPRNG", () => {
  for (let i = 0; i < 200; i++) {
    assert.match(R.randomNumericPinNoLeadingZero(6), /^[1-9]\d{5}$/);
    assert.match(R.randomNumericPin(6), /^\d{6}$/);
    assert.match(R.randomToken(32), /^[A-Za-z0-9_-]{43}$/);
  }
  assert.throws(() => R.randomToken(8), RangeError);
  assert.throws(() => R.randomNumericPin(3), RangeError);
});

test("random: uniformInt is unbiased (rejection sampling) - chi-square over a deterministic test stream", () => {
  const rand = deterministicRandom("TEST ONLY uniformInt chi-square");
  const bins = new Array(10).fill(0);
  const N = 50_000;
  for (let i = 0; i < N; i++) bins[R.uniformInt(10, rand)] += 1;
  const chi = bins.reduce((s, o) => s + (o - N / 10) ** 2 / (N / 10), 0);
  assert.ok(chi < 27.88, `chi-square ${chi} (df=9, p=0.001 critical 27.88)`);
  // Rejection actually happens near the limit: a stream of 0xff... is rejected.
  let calls = 0;
  const edge = (n) => (calls++ === 0 ? new Uint8Array(n).fill(0xff) : new Uint8Array(n));
  assert.equal(R.uniformInt(10, edge), 0);
  assert.equal(calls, 2);
});

test("testing: deterministic stream refuses production-looking seeds", () => {
  assert.throws(() => deterministicRandom("my seed"));
});
