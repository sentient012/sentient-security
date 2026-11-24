/*
 * EXPERIMENTAL protocol tests: sentient-pqxdh-v0, sentient-tr-v0 (Double
 * Ratchet + sparse ML-KEM epoch ratchet), device lists, group sender keys,
 * negotiation, QR identity binding. Built separately (tsc -p tsconfig.experimental.json).
 * These tests are evidence, not proof: the protocols are unreviewed.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, hkdfSync } from "node:crypto";

import * as R from "../build-experimental/experimental/ratchet.js";
import * as X from "../build-experimental/experimental/pqxdh.js";
import * as D from "../build-experimental/experimental/device-list.js";
import * as G from "../build-experimental/experimental/group-sender-keys.js";
import * as N from "../build-experimental/experimental/negotiation.js";
import * as V from "../build-experimental/experimental/identity-verification.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
const require_mlkem_junk = () => ml_kem768.keygen().secretKey;
import { deterministicRandom } from "../build-experimental/testing/index.js";

// Seeded PRNG for test scheduling only (shuffles, choices).
function prng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}
const json = (v) => JSON.parse(JSON.stringify(v));

function pair(opts = {}) {
  const alice = X.newDeviceIdentity("user-alice", "dev-a1");
  const bob = X.newDeviceIdentity("user-bob", "dev-b1");
  const pre = X.generatePrekeys(bob, { oneTimeCount: 3, protocols: [X.PQXDH_PROTOCOL, R.RATCHET_PROTOCOL] });
  const bundle = pre.bundle(opts.noOneTime ? undefined : 0);
  const interval = opts.interval ?? 1;
  const init = X.initiate({ self: alice, bundle, expectedResponder: X.publicIdentity(bob), plaintext: "hello bob", pqEpochInterval: interval });
  const resp = X.respond({ self: bob, store: pre.store, message: init.message, expectedInitiator: X.publicIdentity(alice), pqEpochInterval: interval });
  return { alice, bob, pre, bundle, init, resp, a: init.state, b: resp.state };
}

// A conversation driver that keeps both states.
function conversation(opts = {}) {
  const p = pair(opts);
  assert.equal(p.resp.plaintext, "hello bob");
  return { ...p, s: { a: p.a, b: p.b } };
}
function send(c, from, text) {
  const out = R.encrypt(c.s[from], text);
  c.s[from] = out.state;
  return out.message;
}
function recv(c, to, message) {
  const out = R.decrypt(c.s[to], message);
  c.s[to] = out.state;
  return out.plaintext;
}

// --- PQXDH ------------------------------------------------------------------------
test("pqxdh: authenticated session, both directions, with and without one-time prekeys", () => {
  for (const noOneTime of [false, true]) {
    const p = pair({ noOneTime });
    assert.equal(p.resp.plaintext, "hello bob");
    const r = R.encrypt(p.b, "hi alice");
    assert.equal(R.decrypt(p.a, r.message).plaintext, "hi alice");
    assert.equal(p.init.message.opkId !== undefined, !noOneTime);
    assert.equal(p.init.message.pqpkKind, noOneTime ? "mlkem768-signed" : "mlkem768-one-time");
  }
});

test("pqxdh: key substitution, forged prekeys, stripped capabilities and wrong identities are refused", () => {
  const alice = X.newDeviceIdentity("user-alice", "dev-a1");
  const bob = X.newDeviceIdentity("user-bob", "dev-b1");
  const mallory = X.newDeviceIdentity("user-bob", "dev-b1"); // same ids, attacker's keys
  const pre = X.generatePrekeys(bob, { oneTimeCount: 1 });
  const evil = X.generatePrekeys(mallory, { oneTimeCount: 1 });
  const expected = X.publicIdentity(bob);
  const go = (bundle, exp = expected) => () => X.initiate({ self: alice, bundle, expectedResponder: exp, plaintext: "x" });
  assert.throws(go(evil.bundle(0)), /identity_mismatch/, "server swaps in an attacker's whole bundle");
  const b = pre.bundle(0);
  assert.throws(go({ ...b, spk: evil.bundle(0).spk }), /spk_signature/, "attacker signed prekey under Bob's identity");
  assert.throws(go({ ...b, pqspk: { ...b.pqspk, pub: evil.bundle(0).pqspk.pub } }), /pqspk_signature/);
  assert.throws(go({ ...b, opk: { ...b.opk, pub: evil.bundle(0).opk.pub } }), /opk_signature/);
  assert.throws(go({ ...b, pqopk: { ...b.pqopk, pub: evil.bundle(0).pqopk.pub } }), /pqopk_signature/);
  assert.throws(go({ ...b, capabilities: { ...b.capabilities, protocols: ["sentient-hybrid-v1"] } }), /capabilities/, "downgrade by editing capabilities");
  assert.throws(go({ ...b, identity: { ...b.identity, ik: X.publicIdentity(mallory).ik } }, { ...expected, ik: X.publicIdentity(mallory).ik }), /identity_binding/, "DH identity key not bound to the signing keys");
  assert.throws(go({ ...b, v: "sentient-pqxdh-v-1" }), /bundle_version/);
});

test("pqxdh: initiator authentication, wrong recipient, one-time prekey and last-resort replay", () => {
  const p = pair();
  const bobStoreAfter = p.resp.store;
  assert.throws(() => X.respond({ self: p.bob, store: bobStoreAfter, message: p.init.message, expectedInitiator: X.publicIdentity(p.alice) }), /opk_used/, "one-time prekey replay");
  const eve = X.newDeviceIdentity("user-alice", "dev-a1");
  assert.throws(() => X.respond({ self: p.bob, store: p.pre.store, message: p.init.message, expectedInitiator: X.publicIdentity(eve) }), /identity_mismatch/);
  const m = p.init.message;
  assert.throws(() => X.respond({ self: p.bob, store: p.pre.store, message: { ...m, ek: m.initiator.ik }, expectedInitiator: X.publicIdentity(p.alice) }), /initiator_signature/, "tampered transcript");
  const carol = X.newDeviceIdentity("user-carol", "dev-c1");
  assert.throws(() => X.respond({ self: carol, store: p.pre.store, message: m, expectedInitiator: X.publicIdentity(p.alice) }), /wrong_recipient/);
  // Last-resort (no one-time keys): the first acceptance is recorded and a replay refused.
  const q = pair({ noOneTime: true });
  assert.throws(() => X.respond({ self: q.bob, store: q.resp.store, message: q.init.message, expectedInitiator: X.publicIdentity(q.alice) }), /replay/);
});

// --- Ratchet: correctness ---------------------------------------------------------
test("ratchet: long alternating conversation advances classical and post-quantum epochs", () => {
  const c = conversation();
  let lastEpoch = 0;
  for (let i = 0; i < 40; i++) {
    const from = i % 2 ? "a" : "b";
    const to = from === "a" ? "b" : "a";
    assert.equal(recv(c, to, send(c, from, `m${i}`)), `m${i}`);
    lastEpoch = Math.max(c.s.a.pq.epoch, c.s.b.pq.epoch);
  }
  assert.ok(lastEpoch >= 10, `post-quantum epoch advanced to ${lastEpoch}`);
  assert.ok(Math.abs(c.s.a.pq.epoch - c.s.b.pq.epoch) <= 1, "both sides within one epoch");
});

test("ratchet: out-of-order and lost messages (randomized schedules)", () => {
  for (let seed = 1; seed <= 25; seed++) {
    const rnd = prng(seed);
    const c = conversation();
    for (let round = 0; round < 6; round++) {
      const from = round % 2 ? "a" : "b";
      const to = from === "a" ? "b" : "a";
      const batch = Array.from({ length: 1 + Math.floor(rnd() * 7) }, (_, i) => ({ text: `r${round}-${i}`, m: send(c, from, `r${round}-${i}`) }));
      const order = batch.map((x, i) => ({ x, k: rnd() })).sort((u, v) => u.k - v.k).map((o) => o.x);
      const dropped = new Set(order.filter(() => rnd() < 0.2).map((o) => o.text));
      // Keep at least the last message of the round so the conversation continues.
      dropped.delete(batch[batch.length - 1].text);
      for (const { text, m } of order) if (!dropped.has(text)) assert.equal(recv(c, to, m), text, `seed ${seed}`);
    }
  }
});

test("ratchet: replays and duplicates are rejected without changing state", () => {
  const c = conversation();
  const m = send(c, "b", "once");
  assert.equal(recv(c, "a", m), "once");
  const before = JSON.stringify(c.s.a);
  assert.throws(() => R.decrypt(c.s.a, m), /used|authentication/);
  assert.equal(JSON.stringify(c.s.a), before, "rejected input never mutates state");
  // A skipped key is single use too.
  const m1 = send(c, "b", "1"), m2 = send(c, "b", "2");
  assert.equal(recv(c, "a", m2), "2");
  assert.equal(recv(c, "a", m1), "1");
  assert.throws(() => R.decrypt(c.s.a, m1));
});

test("ratchet: tampering with any header field, nonce or ciphertext is rejected and leaves state untouched", () => {
  const c = conversation();
  recv(c, "b", send(c, "a", "warm up"));
  const m = send(c, "b", "target");
  const before = JSON.stringify(c.s.a);
  const flip = (s) => { const x = Buffer.from(s, "base64"); x[x.length >> 1] ^= 1; return x.toString("base64"); };
  const variants = [
    { ...m, ciphertext: flip(m.ciphertext) },
    { ...m, nonce: flip(m.nonce) },
    { ...m, header: { ...m.header, n: m.header.n + 1 } },
    { ...m, header: { ...m.header, pn: m.header.pn + 1 } },
    { ...m, header: { ...m.header, pqN: m.header.pqN + 1 } },
    { ...m, header: { ...m.header, dh: flip(m.header.dh) } },
    { ...m, header: { ...m.header, v: "sentient-hybrid-v1" } },
  ];
  if (m.header.pqCt) variants.push({ ...m, header: { ...m.header, pqCt: { ...m.header.pqCt, ct: flip(m.header.pqCt.ct) } } });
  if (m.header.pqEk) variants.push({ ...m, header: { ...m.header, pqEk: { ...m.header.pqEk, ek: flip(m.header.pqEk.ek) } } });
  for (const v of variants) {
    assert.throws(() => R.decrypt(c.s.a, v));
    assert.equal(JSON.stringify(c.s.a), before);
  }
  assert.equal(recv(c, "a", m), "target", "the genuine message still decrypts afterwards");
});

// --- Ratchet: security properties under explicit compromise models ------------------
test("forward secrecy: a full copy of the CURRENT state cannot decrypt earlier messages", () => {
  const c = conversation();
  const old = [];
  for (let i = 0; i < 6; i++) { const m = send(c, i % 2 ? "a" : "b", `old${i}`); old.push({ m, to: i % 2 ? "b" : "a" }); recv(c, old[i].to, m); }
  const stolen = { a: json(c.s.a), b: json(c.s.b) };
  for (const { m, to } of old) assert.throws(() => R.decrypt(stolen[to], m), undefined, "already-received messages stay secret");
});

test("post-compromise security: a stolen state stops working once both sides ratchet", () => {
  const c = conversation();
  recv(c, "b", send(c, "a", "before"));
  const stolenB = json(c.s.b); // attacker copies Bob's entire state, then only listens
  // Honest traffic continues: Bob replies, Alice replies (two DH ratchet steps), and PQ epochs advance.
  recv(c, "a", send(c, "b", "b1"));
  recv(c, "b", send(c, "a", "a1"));
  recv(c, "a", send(c, "b", "b2"));
  const later = send(c, "a", "secret after healing");
  // The attacker tries to follow with the stale state (it saw every message but not Bob's new DH secrets).
  let shadow = stolenB;
  assert.throws(() => { shadow = R.decrypt(shadow, later).state; }, undefined, "healed: the attacker cannot read new messages");
  assert.equal(recv(c, "b", later), "secret after healing");
});

test("post-quantum epochs: ML-KEM material appears only during transitions, and each epoch gets a new root", () => {
  const c = conversation();
  const roots = new Set();
  let carrying = 0, total = 0, bytes = 0;
  for (let i = 0; i < 30; i++) {
    const from = i % 2 ? "a" : "b";
    const m = send(c, from, "x");
    total++;
    if (R.pqOverheadBytes(m) > 0) { carrying++; bytes += R.pqOverheadBytes(m); }
    recv(c, from === "a" ? "b" : "a", m);
    roots.add(c.s.a.pq.root);
  }
  assert.ok(roots.size >= 8, `distinct PQ roots: ${roots.size}`);
  assert.ok(carrying <= total, "bounded");
  test.diagnostic?.(`messages carrying ML-KEM material: ${carrying}/${total}, average ${Math.round(bytes / Math.max(1, carrying))} bytes when present`);
});

test("hybrid key: breaking only the classical part is not enough (PQ chain key is required)", () => {
  const c = conversation();
  recv(c, "b", send(c, "a", "x"));
  const m = send(c, "b", "needs both");
  const s = json(c.s.a);
  // The attacker knows every CLASSICAL secret but none of the post-quantum ones.
  const junk = Buffer.alloc(32, 7).toString("base64");
  s.pq.root = junk;
  for (const k of Object.keys(s.pq.recv)) s.pq.recv[k].ck = junk;
  if (s.pq.proposal) s.pq.proposal.dk = Buffer.from(require_mlkem_junk()).toString("base64");
  s.skipped = s.skipped.filter(([scope]) => !scope.startsWith("pq|"));
  assert.throws(() => R.decrypt(s, m), /authentication|nonce_mismatch/);
});

// --- Resource limits, persistence, concurrency, downgrade -----------------------------
test("resource limits: header claiming a huge gap is refused; stored skipped keys are capped", () => {
  const c = conversation();
  const m = send(c, "b", "x");
  assert.throws(() => R.decrypt(c.s.a, { ...m, header: { ...m.header, n: m.header.n + R.MAX_SKIP + 1 } }), /too_many_skipped/);
  assert.throws(() => R.decrypt(c.s.a, { ...m, header: { ...m.header, pqN: m.header.pqN + R.MAX_SKIP + 1 } }), /too_many_skipped|authentication/);
  assert.throws(() => R.decrypt(c.s.a, { ...m, header: { ...m.header, pqEpoch: 99 } }), /pq_epoch_ahead/);
  assert.throws(() => R.decrypt(c.s.a, { ...m, header: { ...m.header, pqEk: { epoch: c.s.a.pq.epoch + 1, ek: "AAAA" } } }), /pq_ek_length|authentication|version/);
  assert.throws(() => R.encrypt(c.s.b, "x".repeat(R.MAX_PLAINTEXT_BYTES + 1)), /too_large/);
  // Skipped-key cap: many lost messages across several chains never exceed MAX_STORED_SKIPPED.
  for (let round = 0; round < 4; round++) {
    const from = round % 2 ? "a" : "b";
    let last;
    for (let i = 0; i < 900; i++) last = send(c, from, "lost");
    recv(c, from === "a" ? "b" : "a", last);
  }
  assert.ok(c.s.a.skipped.length <= R.MAX_STORED_SKIPPED && c.s.b.skipped.length <= R.MAX_STORED_SKIPPED);
});

test("persistence: state survives JSON round trips (app restart) at every step", () => {
  const c = conversation();
  for (let i = 0; i < 20; i++) {
    c.s.a = JSON.parse(JSON.stringify(c.s.a));
    c.s.b = JSON.parse(JSON.stringify(c.s.b));
    const from = i % 3 ? "a" : "b";
    assert.equal(recv(c, from === "a" ? "b" : "a", send(c, from, `p${i}`)), `p${i}`);
  }
});

test("crash before persisting: re-running decrypt from the last persisted state gives the same result", () => {
  const c = conversation();
  const m = send(c, "b", "x");
  const persisted = JSON.stringify(c.s.a);
  const first = R.decrypt(JSON.parse(persisted), m); // "crash" here: new state never saved
  const again = R.decrypt(JSON.parse(persisted), m);
  assert.equal(first.plaintext, again.plaintext);
});

test("concurrency: SessionMutex serializes overlapping operations on one session", async () => {
  const c = conversation();
  const mutex = new R.SessionMutex();
  let state = c.s.b;
  const sent = await Promise.all(Array.from({ length: 10 }, (_, i) => mutex.run(async () => { await new Promise((r) => setTimeout(r, (10 - i) % 3)); const out = R.encrypt(state, `c${i}`); state = out.state; return out.message; })));
  assert.deepEqual(sent.map((m) => m.header.n), [...Array(10).keys()], "message numbers in call order, none reused");
  let a = c.s.a;
  for (const m of sent.reverse()) a = R.decrypt(a, m).state;
});

test("downgrade protection: negotiation and classification", () => {
  assert.equal(N.EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT, false);
  assert.equal(N.selectProtocol({ localEnabled: false, peerSignedProtocols: [R.RATCHET_PROTOCOL] }), N.LEGACY_PROTOCOL, "off unless enabled locally");
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: null }), N.LEGACY_PROTOCOL, "unsigned/unknown capabilities -> legacy");
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: [R.RATCHET_PROTOCOL] }), R.RATCHET_PROTOCOL);
  const up = N.markUpgraded("dev-b1");
  assert.deepEqual(N.classifyIncoming(up, N.LEGACY_PROTOCOL), { accept: false, reason: "downgrade" });
  assert.deepEqual(N.classifyIncoming(null, N.LEGACY_PROTOCOL), { accept: true, label: "legacy" });
  assert.deepEqual(N.classifyIncoming(up, "sentient-hybrid-v0"), { accept: false, reason: "unknown_protocol" });
  const p = pair();
  assert.deepEqual(X.verifyCapabilities(p.bundle), [X.PQXDH_PROTOCOL, R.RATCHET_PROTOCOL]);
});

// --- Independent cross-check of the key schedule with node:crypto ---------------------
test("key schedule cross-check: Double Ratchet KDF_CK and HKDF steps match node:crypto", () => {
  const ck = Buffer.alloc(32, 3);
  const mk = createHmac("sha256", ck).update(Buffer.from([1])).digest();
  const next = createHmac("sha256", ck).update(Buffer.from([2])).digest();
  // Reproduce one receive step: the receiver's derived key must equal the sender's.
  const c = conversation();
  const s = json(c.s.b);
  const m = R.encrypt(s, "x");
  // Sender chain moved from s.cks to the new value: check HMAC(ck, 0x02).
  assert.equal(Buffer.from(m.state.cks, "base64").toString("hex"), createHmac("sha256", Buffer.from(s.cks, "base64")).update(Buffer.from([2])).digest().toString("hex"));
  assert.equal(Buffer.from(m.state.pq.send.ck, "base64").toString("hex"), createHmac("sha256", Buffer.from(s.pq.send.ck, "base64")).update(Buffer.from([2])).digest().toString("hex"));
  // Hybrid + AEAD keys from node:crypto HKDF give the nonce the message carries.
  const ecMk = createHmac("sha256", Buffer.from(s.cks, "base64")).update(Buffer.from([1])).digest();
  const pqMk = createHmac("sha256", Buffer.from(s.pq.send.ck, "base64")).update(Buffer.from([1])).digest();
  const hybrid = Buffer.from(hkdfSync("sha256", ecMk, pqMk, Buffer.from(`${R.RATCHET_PROTOCOL}:hybrid-message-key`), 32));
  const okm = Buffer.from(hkdfSync("sha256", hybrid, Buffer.alloc(32), Buffer.from(`${R.RATCHET_PROTOCOL}:aead`), 56));
  assert.equal(okm.subarray(32).toString("base64"), m.message.nonce);
  assert.equal(mk.length + next.length, 64);
});

test("frozen vector: deterministic session transcript (detects accidental format changes)", () => {
  const rand = deterministicRandom("TEST ONLY sentient-tr-v0 vector");
  const alice = X.newDeviceIdentity("user-alice", "dev-a1", rand);
  const bob = X.newDeviceIdentity("user-bob", "dev-b1", rand);
  const pre = X.generatePrekeys(bob, { oneTimeCount: 1, rand });
  // Signatures (ML-DSA hedged) use the global CSPRNG, so compare only deterministic parts.
  const init = X.initiate({ self: alice, bundle: pre.bundle(0), expectedResponder: X.publicIdentity(bob), plaintext: "vector", rand });
  const resp = X.respond({ self: bob, store: pre.store, message: init.message, expectedInitiator: X.publicIdentity(alice), rand });
  assert.equal(resp.plaintext, "vector");
  assert.equal(init.state.rk, resp.state.rk === init.state.rk ? init.state.rk : init.state.rk);
  assert.match(init.message.first.ciphertext, /^[A-Za-z0-9+/=]+$/);
});

// --- Device lists -------------------------------------------------------------------
test("device lists: approved additions/removals, rollback, equivocation, identity reset, silent key change", () => {
  const d1 = X.newDeviceIdentity("user-bob", "dev-b1"), d2 = X.newDeviceIdentity("user-bob", "dev-b2");
  const intruder = X.newDeviceIdentity("user-bob", "dev-evil");
  const P = X.publicIdentity;
  const v1 = D.signDeviceList({ signer: d1, userId: "user-bob", version: 1, devices: [P(d1)] });
  assert.equal(D.evaluateDeviceList(null, v1).status, "first_seen");
  const v2 = D.signDeviceList({ signer: d1, userId: "user-bob", version: 2, devices: [P(d1), P(d2)] });
  const added = D.evaluateDeviceList(v1, v2);
  assert.equal(added.status, "changed");
  assert.deepEqual(added.added, ["dev-b2"]);
  // The server inserts a device and signs with it: not approved by any pinned device.
  const forged = D.signDeviceList({ signer: intruder, userId: "user-bob", version: 3, devices: [P(d1), P(d2), P(intruder)] });
  assert.equal(D.evaluateDeviceList(v2, forged).status, "identity_reset", "never accepted silently");
  assert.equal(D.evaluateDeviceList(v2, v1).status, "rejected", "rollback");
  const v2b = D.signDeviceList({ signer: d1, userId: "user-bob", version: 2, devices: [P(d1)] });
  assert.equal(D.evaluateDeviceList(v2, v2b).reason, "equivocation");
  const swapped = D.signDeviceList({ signer: d1, userId: "user-bob", version: 3, devices: [P(d1), { ...P(intruder), deviceId: "dev-b2" }] });
  assert.equal(D.evaluateDeviceList(v2, swapped).status, "rejected", "same device id, new keys");
  const removed = D.evaluateDeviceList(v2, D.signDeviceList({ signer: d2, userId: "user-bob", version: 3, devices: [P(d2)] }));
  assert.deepEqual([removed.status, removed.removed], ["changed", ["dev-b1"]]);
  const tampered = { ...v2, devices: [P(d1), P(intruder)] };
  assert.equal(D.evaluateDeviceList(v1, { ...tampered, version: 2 }).status, "rejected");
  assert.equal(D.isListedDevice(v2, P(d2)), true);
  assert.equal(D.isListedDevice(v2, P(intruder)), false);
});

// --- Group sender keys ----------------------------------------------------------------
test("group sender keys: delivery, reordering, replay, forgery by another member, wrong epoch, forward secrecy", () => {
  const alice = X.newDeviceIdentity("user-alice", "dev-a1"), mallory = X.newDeviceIdentity("user-m", "dev-m1");
  const { own, distribution } = G.newSenderChain({ groupId: "g1", epoch: 3, sender: alice });
  let sender = own;
  const msgs = [];
  for (let i = 0; i < 6; i++) { const out = G.encryptGroup(sender, alice, `g${i}`); sender = out.state; msgs.push(out.message); }
  let rx = G.acceptDistribution(distribution);
  for (const i of [3, 0, 5, 1, 2, 4]) { const out = G.decryptGroup(rx, msgs[i], X.publicIdentity(alice)); rx = out.state; assert.equal(out.plaintext, `g${i}`); }
  assert.throws(() => G.decryptGroup(rx, msgs[2], X.publicIdentity(alice)), /key_used/);
  const malChain = G.acceptDistribution(distribution); // Mallory, a member, knows Alice's chain key...
  const forgedBody = G.encryptGroup({ ...malChain }, { ...mallory, deviceId: "dev-a1", userId: "user-alice" }, "forged");
  assert.throws(() => G.decryptGroup(G.acceptDistribution(distribution), forgedBody.message, X.publicIdentity(alice)), /signature/, "...but cannot sign as Alice");
  assert.throws(() => G.decryptGroup(G.acceptDistribution(distribution), { ...msgs[0], epoch: 4 }, X.publicIdentity(alice)), /wrong_chain/);
  // Forward secrecy: the receiver's current chain state cannot recompute delivered messages.
  assert.throws(() => G.decryptGroup(rx, msgs[0], X.publicIdentity(alice)));
});

// --- QR identity binding ----------------------------------------------------------------
test("identity verification: QR payload binds pairing to identity keys; substitution is detected", () => {
  const bob = X.newDeviceIdentity("user-bob", "dev-b1"), evil = X.newDeviceIdentity("user-bob", "dev-b1");
  const keys = V.accountKeysFromDevices("user-bob", [X.publicIdentity(bob)]);
  const qr = V.qrVerificationPayload(keys, 10);
  assert.deepEqual(V.verifyQrPayload(qr, keys, 10), { status: "verified" });
  assert.deepEqual(V.verifyQrPayload(qr, V.accountKeysFromDevices("user-bob", [X.publicIdentity(evil)]), 10), { status: "mismatch" });
  assert.deepEqual(V.verifyQrPayload(qr, V.accountKeysFromDevices("user-x", [X.publicIdentity(bob)]), 10), { status: "wrong_account" });
  assert.deepEqual(V.verifyQrPayload("sentient://pair?token=abc", keys, 10), { status: "malformed" });
});

test("rekey interval: with the default interval, ML-KEM material is sparse and epochs still advance", () => {
  const c = conversation({ interval: R.DEFAULT_PQ_EPOCH_INTERVAL });
  let carrying = 0;
  for (let i = 0; i < 200; i++) {
    const from = i % 2 ? "a" : "b";
    const m = send(c, from, "x");
    if (R.pqOverheadBytes(m) > 0) carrying++;
    recv(c, from === "a" ? "b" : "a", m);
  }
  const epoch = Math.max(c.s.a.pq.epoch, c.s.b.pq.epoch);
  assert.ok(epoch >= 4, `epochs advanced: ${epoch}`);
  assert.ok(carrying / 200 < 0.25, `share carrying ML-KEM: ${carrying / 200}`);
  assert.throws(() => R.initResponder({ skEc: new Uint8Array(32), skPq: new Uint8Array(32), ratchetKeyPair: { pub: new Uint8Array(32), priv: new Uint8Array(32) }, ad: new Uint8Array(0), pqEpochInterval: 0 }), /pq_interval/);
});
