/*
 * Regression tests for the integration defects found by the 2026-11-25 audit
 * (E-1 to E-6, E-8). Each test first
 * states the old failure, then checks the fix.
 */
import test from "node:test";
import assert from "node:assert/strict";
import * as R from "../build-experimental/experimental/ratchet.js";
import * as X from "../build-experimental/experimental/pqxdh.js";
import * as D from "../build-experimental/experimental/device-list.js";
import * as G from "../build-experimental/experimental/group-sender-keys.js";
import * as N from "../build-experimental/experimental/negotiation.js";
import { randomBytes } from "node:crypto";

const rnd = (n) => new Uint8Array(randomBytes(n));
const DAY = 24 * 60 * 60 * 1000;

test("E-1: a bundle with DEFAULT options negotiates the session suite (was: always legacy)", () => {
  const bob = X.newDeviceIdentity("bob", "b1");
  const signed = X.verifyCapabilities(X.generatePrekeys(bob, { oneTimeCount: 1 }).bundle(0));
  assert.deepEqual(signed, [X.PQXDH_PROTOCOL, R.RATCHET_PROTOCOL]);
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: signed }), R.RATCHET_PROTOCOL);
  // A bundle that signs only the key-agreement id (older default) also selects the suite.
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: [X.PQXDH_PROTOCOL] }), R.RATCHET_PROTOCOL);
  assert.equal(N.selectProtocol({ localEnabled: false, peerSignedProtocols: signed }), N.LEGACY_PROTOCOL, "still off unless enabled");
});

test("E-2: an upgraded pin never selects legacy; a withheld or stripped bundle blocks sending (was: silent hybrid-v1)", () => {
  const pin = N.markUpgraded("bob");
  assert.equal(pin.peerUserId, "bob");
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: null, pin }), "blocked");
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: [N.LEGACY_PROTOCOL], pin }), "blocked");
  assert.equal(N.selectProtocol({ localEnabled: false, peerSignedProtocols: null, pin }), "blocked", "even if the local flag is turned off later");
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: [R.RATCHET_PROTOCOL], pin }), R.RATCHET_PROTOCOL);
  // Receiving side unchanged; clearing needs an explicit reset.
  assert.deepEqual(N.classifyIncoming(pin, N.LEGACY_PROTOCOL), { accept: false, reason: "downgrade" });
  const cleared = N.clearUpgrade(pin);
  assert.equal(N.selectProtocol({ localEnabled: true, peerSignedProtocols: null, pin: cleared }), N.LEGACY_PROTOCOL);
});

test("E-3: signed-prekey rotation keeps in-flight initial messages working for the grace period (was: unknown_spk)", () => {
  const alice = X.newDeviceIdentity("alice", "a1"), bob = X.newDeviceIdentity("bob", "b1");
  const pre = X.generatePrekeys(bob, { oneTimeCount: 2 });
  const t0 = new Date("2026-12-01T00:00:00Z");
  const inFlight = X.initiate({ self: alice, bundle: pre.bundle(0), expectedResponder: X.publicIdentity(bob), plaintext: "sent before rotation" }).message;
  const lastResortOnly = X.initiate({ self: alice, bundle: pre.bundle(), expectedResponder: X.publicIdentity(bob), plaintext: "no one-time keys" }).message;
  const rotated = X.rotateSignedPrekeys(bob, pre.store, { now: t0 });
  assert.notEqual(rotated.spk.id, pre.store.spk.id);
  // New bundles use the new signed prekeys and verify.
  const fresh = X.buildBundle({ identity: X.publicIdentity(bob), capabilities: X.signCapabilities(bob), spk: rotated.spk, pqspk: rotated.pqspk });
  const viaNew = X.initiate({ self: alice, bundle: fresh, expectedResponder: X.publicIdentity(bob), plaintext: "after rotation" }).message;
  let store = rotated.store;
  const r1 = X.respond({ self: bob, store, message: inFlight, expectedInitiator: X.publicIdentity(alice), now: new Date(t0.getTime() + DAY) });
  assert.equal(r1.plaintext, "sent before rotation");
  store = r1.store;
  const r2 = X.respond({ self: bob, store, message: viaNew, expectedInitiator: X.publicIdentity(alice), now: new Date(t0.getTime() + DAY) });
  assert.equal(r2.plaintext, "after rotation");
  // After the grace period the retired key is gone and refused.
  assert.throws(() => X.respond({ self: bob, store: r2.store, message: lastResortOnly, expectedInitiator: X.publicIdentity(alice), now: new Date(t0.getTime() + X.SIGNED_PREKEY_GRACE_MS + DAY) }), /unknown_spk/);
  // Re-publishing after a restart yields the same public keys.
  const pub = X.publicSignedPrekeys(bob, rotated.store);
  assert.equal(pub.spk.pub, rotated.spk.pub);
  assert.equal(pub.pqspk.pub, rotated.pqspk.pub);
});

test("E-3: one-time prekey replenishment; consumed keys cannot be reused", () => {
  const alice = X.newDeviceIdentity("alice", "a1"), bob = X.newDeviceIdentity("bob", "b1");
  const pre = X.generatePrekeys(bob, { oneTimeCount: 0 });
  const more = X.addOneTimePrekeys(bob, pre.store, 2);
  assert.equal(Object.keys(more.store.opks).length, 2);
  const pubSigned = X.publicSignedPrekeys(bob, more.store);
  const bundle = X.buildBundle({ identity: X.publicIdentity(bob), capabilities: X.signCapabilities(bob), ...pubSigned, opk: more.opks[0], pqopk: more.pqopks[0] });
  const m = X.initiate({ self: alice, bundle, expectedResponder: X.publicIdentity(bob), plaintext: "otk" }).message;
  const r = X.respond({ self: bob, store: more.store, message: m, expectedInitiator: X.publicIdentity(alice) });
  assert.equal(Object.keys(r.store.opks).length, 1);
  assert.throws(() => X.respond({ self: bob, store: r.store, message: m, expectedInitiator: X.publicIdentity(alice) }), /opk_used/);
  assert.throws(() => X.addOneTimePrekeys(bob, more.store, X.MAX_ONE_TIME_PREKEYS), /prekey_count/);
});

test("E-8: last-resort replay records are bound to their signed prekey and pruned with it", () => {
  const alice = X.newDeviceIdentity("alice", "a1"), bob = X.newDeviceIdentity("bob", "b1");
  const pre = X.generatePrekeys(bob, { oneTimeCount: 0 });
  const m = X.initiate({ self: alice, bundle: pre.bundle(), expectedResponder: X.publicIdentity(bob), plaintext: "x" }).message;
  const r = X.respond({ self: bob, store: pre.store, message: m, expectedInitiator: X.publicIdentity(alice) });
  assert.ok(r.store.seenInitial[0].startsWith(`${pre.store.spk.id}|`));
  assert.throws(() => X.respond({ self: bob, store: r.store, message: m, expectedInitiator: X.publicIdentity(alice) }), /replay/);
  const t0 = new Date();
  const rotated = X.rotateSignedPrekeys(bob, r.store, { now: t0 });
  assert.throws(() => X.respond({ self: bob, store: rotated.store, message: m, expectedInitiator: X.publicIdentity(alice), now: t0 }), /replay/, "still a replay during grace");
  const later = X.pruneRetiredPrekeys(rotated.store, new Date(t0.getTime() + X.SIGNED_PREKEY_GRACE_MS + 1));
  assert.equal(later.seenInitial.length, 0);
  assert.throws(() => X.respond({ self: bob, store: later, message: m, expectedInitiator: X.publicIdentity(alice) }), /unknown_spk/, "and after grace the key itself is gone");
});

test("E-4: device lists expire; a frozen list becomes 'stale' (was: 'unchanged' forever)", () => {
  const d1 = X.newDeviceIdentity("bob", "b1");
  const issued = new Date("2026-12-01T00:00:00Z");
  const v1 = D.signDeviceList({ signer: d1, userId: "bob", version: 1, devices: [X.publicIdentity(d1)], issuedAt: issued.toISOString() });
  assert.equal(D.evaluateDeviceList(v1, v1, { now: new Date(issued.getTime() + DAY) }).status, "unchanged");
  assert.equal(D.evaluateDeviceList(v1, v1, { now: new Date(issued.getTime() + D.DEVICE_LIST_LIFETIME_MS + 1) }).status, "stale");
  assert.equal(D.evaluateDeviceList(null, v1, { now: new Date(issued.getTime() + D.DEVICE_LIST_LIFETIME_MS + 1) }).reason, "expired", "an expired list is never pinned first");
  // Refresh: same devices, new version, fresh expiry, accepted as a change with no device diff.
  assert.equal(D.needsRefresh(v1, new Date(issued.getTime() + D.DEVICE_LIST_REFRESH_MS)), true);
  const v2 = D.refreshDeviceList(v1, d1, new Date(issued.getTime() + D.DEVICE_LIST_REFRESH_MS));
  const verdict = D.evaluateDeviceList(v1, v2, { now: new Date(issued.getTime() + D.DEVICE_LIST_REFRESH_MS) });
  assert.equal(verdict.status, "changed");
  assert.deepEqual([verdict.added, verdict.removed], [[], []]);
  // Tampering with the signed expiry breaks the signature.
  assert.equal(D.evaluateDeviceList(v1, { ...v2, expiresAt: "2099-01-01T00:00:00.000Z" }, { now: new Date(issued.getTime() + DAY) }).status, "rejected");
});

test("E-4: fork detection by gossip: the same version with a different digest is equivocation", () => {
  const d1 = X.newDeviceIdentity("bob", "b1"), d2 = X.newDeviceIdentity("bob", "b2"), evil = X.newDeviceIdentity("bob", "evil");
  const v1 = D.signDeviceList({ signer: d1, userId: "bob", version: 1, devices: [X.publicIdentity(d1)] });
  const forCarol = D.signDeviceList({ signer: d1, userId: "bob", version: 2, devices: [X.publicIdentity(d1), X.publicIdentity(d2)] });
  // A compromised-signer fork shown only to Alice (version 2 as well).
  const forAlice = D.signDeviceList({ signer: d1, userId: "bob", version: 2, devices: [X.publicIdentity(d1), X.publicIdentity(evil)] });
  assert.deepEqual(D.compareGossip(forCarol, { version: 2, digest: D.deviceListDigest(forCarol) }), { status: "consistent" });
  assert.deepEqual(D.compareGossip(forAlice, { version: 2, digest: D.deviceListDigest(forCarol) }), { status: "equivocation", version: 2 });
  assert.deepEqual(D.compareGossip(v1, { version: 2, digest: D.deviceListDigest(forCarol) }), { status: "peer_ahead", version: 2 });
  assert.deepEqual(D.compareGossip(forCarol, { version: 1, digest: D.deviceListDigest(v1) }), { status: "peer_behind" });
});

test("E-5: a sender-key hand-off is accepted only for its authenticated session peer (was: any claimed sender)", () => {
  const alice = X.newDeviceIdentity("alice", "a1");
  const { distribution } = G.newSenderChain({ groupId: "g", epoch: 2, sender: alice });
  assert.throws(() => G.acceptDistribution(distribution), /unauthenticated/);
  assert.throws(() => G.acceptDistribution(distribution, { userId: "mallory", deviceId: "m1" }), /wrong_sender/, "Mallory relays Alice's chain as if it were hers");
  const victimClaim = { ...distribution, senderUserId: "victim", senderDeviceId: "v1", chainKey: Buffer.from(rnd(32)).toString("base64") };
  assert.throws(() => G.acceptDistribution(victimClaim, { userId: "mallory", deviceId: "m1" }), /wrong_sender/, "the audit PoC (F6)");
  assert.throws(() => G.acceptDistribution(distribution, { userId: "alice", deviceId: "a1" }, { groupId: "g", epoch: 3 }), /wrong_chain/);
  assert.equal(G.acceptDistribution(distribution, { userId: "alice", deviceId: "a1" }, { groupId: "g", epoch: 2 }).senderUserId, "alice");
});

test("E-6: a message delayed across two PQ epoch transitions still decrypts (was: pq_epoch_expired)", () => {
  const alice = X.newDeviceIdentity("alice", "a1"), bob = X.newDeviceIdentity("bob", "b1");
  const pre = X.generatePrekeys(bob, { oneTimeCount: 1 });
  let { state: a, message } = X.initiate({ self: alice, bundle: pre.bundle(0), expectedResponder: X.publicIdentity(bob), plaintext: "hi", pqEpochInterval: 1 });
  let { state: b } = X.respond({ self: bob, store: pre.store, message, expectedInitiator: X.publicIdentity(alice), pqEpochInterval: 1 });
  // Alice writes a message in epoch 0 that will be delayed.
  const delayed = R.encrypt(a, "delayed"); a = delayed.state;
  const startEpoch = delayed.message.header.pqEpoch;
  // Ping-pong until both sides are at least 3 epochs further.
  for (let i = 0; i < 12 && Math.min(a.pq.epoch, b.pq.epoch) < startEpoch + 3; i++) {
    const m1 = R.encrypt(a, `a${i}`); a = m1.state; b = R.decrypt(b, m1.message).state;
    const m2 = R.encrypt(b, `b${i}`); b = m2.state; a = R.decrypt(a, m2.message).state;
  }
  assert.ok(b.pq.epoch >= startEpoch + 3, `bob advanced to epoch ${b.pq.epoch}`);
  assert.equal(R.decrypt(b, delayed.message).plaintext, "delayed");
});
