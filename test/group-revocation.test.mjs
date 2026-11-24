/*
 * Group signing-key revocation (sentient-group-*-v1, deployed protocol):
 * which time each check trusts, and what that does and does not guarantee.
 *
 *   message rows : the SERVER row's created_at decides whether the sender key
 *                  was still valid (decryptGroupRows).
 *   wraps / links: the later of the server time and the signer-claimed time
 *                  (trustedTime), or the claimed time when the server supplies none.
 *
 * Under an honest server this stops a revoked key from injecting backdated
 * content. Against a server that is itself malicious (it controls created_at
 * and the directory), no client-side timestamp rule helps; that limitation is
 * stated in THREAT_MODEL.md, and these tests do not claim otherwise.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { base64 } from "@scure/base";

import * as G from "@sentient012/security/group";
import { createSigningDirectory, decryptGroupRows } from "@sentient012/security/group/keys";
import * as B from "@sentient012/security/business";

const b64 = (u) => base64.encode(u);
function member(userId, keyId) {
  const seeds = B.newDeviceSeeds();
  const signing = B.signingKeysFromSeeds(seeds);
  return { userId, keyId, signing, pub: { key_id: keyId, user_id: userId, ed25519_public_key: b64(signing.ed25519PublicKey), ml_dsa_public_key: b64(signing.mlDsaPublicKey) } };
}
const GROUP = "g-1";
const REVOKED_AT = "2026-11-20T12:00:00.000Z";

async function setup() {
  const alice = member("alice", "ka"), bob = member("bob", "kb");
  const gk = G.newGroupKey();
  const directory = createSigningDirectory({ getSigningKeys: async () => [{ ...alice.pub, revoked_at: REVOKED_AT }, { ...bob.pub, revoked_at: null }] });
  await directory.ensure(["ka", "kb"]);
  const row = (sender, id, serverTime, claimedTime = serverTime) => ({
    id, kind: "message", key_epoch: 1, sender_user_id: sender.userId, created_at: serverTime,
    e2ee_payload: G.encryptGroupMessage({ groupKey: gk, header: { groupId: GROUP, epoch: 1, messageId: id, senderId: sender.userId, senderKeyId: sender.keyId, createdAt: claimedTime }, content: { kind: "text", text: id }, signingKeys: sender.signing }),
  });
  const read = (rows) => decryptGroupRows({ rows, keys: new Map([[1, gk]]), directory, groupId: GROUP });
  return { alice, bob, row, read };
}

test("historical messages signed before revocation stay readable", async () => {
  const { alice, row, read } = await setup();
  const [r] = read([row(alice, "old", "2026-11-19T00:00:00.000Z")]);
  assert.equal(r.status, "ok");
});

test("a revoked key cannot add content dated after revocation, even if it backdates its own signed time", async () => {
  const { alice, row, read } = await setup();
  const [r] = read([row(alice, "new", "2026-11-21T00:00:00.000Z", "2026-11-01T00:00:00.000Z")]);
  assert.equal(r.status, "undecryptable");
  assert.equal(r.reason, "unknown_sender_key");
});

test("revocation racing a send: the server's order decides; exactly-at-revocation is rejected", async () => {
  const { alice, row, read } = await setup();
  const results = read([row(alice, "just-before", "2026-11-20T11:59:59.999Z"), row(alice, "at", REVOKED_AT), row(alice, "after", "2026-11-20T12:00:00.001Z")]);
  assert.deepEqual(results.map((x) => x.status), ["ok", "undecryptable", "undecryptable"]);
});

test("other members are unaffected; a key used under another user's name is refused", async () => {
  const { alice, bob, row, read } = await setup();
  const ok = read([row(bob, "b1", "2026-11-22T00:00:00.000Z")]);
  assert.equal(ok[0].status, "ok");
  const impostor = row(bob, "fake", "2026-11-22T00:00:00.000Z");
  impostor.sender_user_id = alice.userId; // server row claims Alice sent Bob-signed content
  assert.equal(read([impostor])[0].reason, "sender_mismatch");
});

test("membership change: a message from a removed member's NEW epoch cannot be read without that epoch key", async () => {
  const { alice, read } = await setup();
  const gk2 = G.newGroupKey();
  const payload = G.encryptGroupMessage({ groupKey: gk2, header: { groupId: GROUP, epoch: 2, messageId: "e2", senderId: alice.userId, senderKeyId: alice.keyId, createdAt: "2026-11-19T00:00:00.000Z" }, content: { kind: "text", text: "x" }, signingKeys: alice.signing });
  const [r] = read([{ id: "e2", kind: "message", key_epoch: 2, sender_user_id: alice.userId, created_at: "2026-11-19T00:00:00.000Z", e2ee_payload: payload }]);
  assert.equal(r.status, "missing_key");
});
