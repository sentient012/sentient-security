/*
 * EXPERIMENTAL: key transparency log (src/experimental/transparency.ts).
 * Built separately: tsc -p tsconfig.experimental.json
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import * as T from "../build-experimental/experimental/transparency.js";
import { newDeviceSeeds, signingKeysFromSeeds, toB64 } from "../build-experimental/business/core.js";

const entries = (n) => Array.from({ length: n }, (_, i) => JSON.stringify({ kind: "identity", seq: i, userId: `u${i}` }));
const tree = (n) => new T.MerkleTree(entries(n).map((e) => T.leafHash(e)));
const hex = (u) => Buffer.from(u).toString("hex");

test("hashing follows RFC 9162: leaf 0x00, node 0x01, empty tree", () => {
  const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest("hex");
  assert.equal(hex(T.leafHash("abc")), sha([0], "abc"));
  const a = T.leafHash("a"), b = T.leafHash("b");
  assert.equal(hex(T.nodeHash(a, b)), sha([1], a, b));
  assert.equal(hex(new T.MerkleTree([]).root()), T.EMPTY_ROOT);
  assert.equal(hex(tree(1).root()), hex(T.leafHash(entries(1)[0])));
  // RFC 6962 shape for 3 leaves: node(node(l0,l1), l2).
  const l = entries(3).map((e) => T.leafHash(e));
  assert.equal(hex(tree(3).root()), hex(T.nodeHash(T.nodeHash(l[0], l[1]), l[2])));
});

test("inclusion proofs verify for every leaf of trees up to 40; any change fails", () => {
  for (let n = 1; n <= 40; n++) {
    const t = tree(n);
    const root = t.root();
    for (let i = 0; i < n; i++) {
      const path = t.inclusionProof(i);
      const leaf = T.leafHash(entries(n)[i]);
      assert.ok(T.verifyInclusion({ index: i, size: n, leaf, path, root }), `n=${n} i=${i}`);
      assert.equal(T.verifyInclusion({ index: i, size: n, leaf: T.leafHash("other"), path, root }), false);
      if (n > 1) assert.equal(T.verifyInclusion({ index: (i + 1) % n, size: n, leaf, path, root }), false, `wrong index n=${n} i=${i}`);
      if (path.length) assert.equal(T.verifyInclusion({ index: i, size: n, leaf, path: path.slice(1), root }), false, "short path");
    }
  }
});

test("consistency proofs verify for every pair of sizes up to 40; a rewritten history fails", () => {
  for (let n = 1; n <= 40; n++) {
    const t = tree(n);
    for (let m = 1; m <= n; m++) {
      const proof = t.consistencyProof(m, n);
      assert.ok(T.verifyConsistency({ first: m, second: n, firstRoot: t.root(m), secondRoot: t.root(n), proof }), `m=${m} n=${n}`);
      if (m < n) {
        // The log rewrote entry 0 after showing the first tree.
        const forged = new T.MerkleTree([T.leafHash("rewritten"), ...entries(n).slice(1).map((e) => T.leafHash(e))]);
        assert.equal(T.verifyConsistency({ first: m, second: n, firstRoot: t.root(m), secondRoot: forged.root(n), proof: forged.consistencyProof(m, n) }), false, `forged m=${m} n=${n}`);
      }
    }
  }
});

test("signed tree heads: pinned log key, append-only, no rollback, no equivocation, fresh", () => {
  const keys = signingKeysFromSeeds(newDeviceSeeds());
  const logKey = { logId: "log-1", ed25519_public_key: toB64(keys.ed25519PublicKey), ml_dsa_public_key: toB64(keys.mlDsaPublicKey) };
  const t = tree(20);
  const now = new Date("2026-11-26T12:00:00Z");
  const head = (size, at = "2026-11-26T11:00:00Z", root = hex(t.root(size))) => T.signTreeHead({ logId: "log-1", size, root, timestamp: at }, keys);
  const h7 = head(7), h20 = head(20, "2026-11-26T11:30:00Z");
  assert.equal(T.evaluateTreeHead(null, h7, [], logKey, { now }).status, "first_seen");
  assert.equal(T.evaluateTreeHead(h7, h20, t.consistencyProof(7, 20), logKey, { now }).status, "advanced");
  assert.equal(T.evaluateTreeHead(h7, head(7, "2026-11-26T11:10:00Z"), [], logKey, { now }).status, "unchanged");
  assert.deepEqual(T.evaluateTreeHead(h20, h7, [], logKey, { now }), { status: "rejected", reason: "rollback" });
  assert.deepEqual(T.evaluateTreeHead(h7, head(7, "2026-11-26T11:10:00Z", "0".repeat(64)), [], logKey, { now }), { status: "rejected", reason: "equivocation" });
  const other = new T.MerkleTree([T.leafHash("x"), ...entries(19).map((e) => T.leafHash(e))]);
  assert.deepEqual(T.evaluateTreeHead(h7, head(20, "2026-11-26T11:30:00Z", hex(other.root(20))), other.consistencyProof(7, 20), logKey, { now }), { status: "rejected", reason: "inconsistent" });
  assert.deepEqual(T.evaluateTreeHead(null, { ...h20, size: 21 }, [], logKey, { now }), { status: "rejected", reason: "signature" });
  const otherKey = signingKeysFromSeeds(newDeviceSeeds());
  assert.deepEqual(T.evaluateTreeHead(null, T.signTreeHead({ logId: "log-1", size: 7, root: hex(t.root(7)), timestamp: "2026-11-26T11:00:00Z" }, otherKey), [], logKey, { now }), { status: "rejected", reason: "signature" });
  assert.deepEqual(T.evaluateTreeHead(null, head(7, "2026-11-24T11:00:00Z"), [], logKey, { now }), { status: "rejected", reason: "stale" });
  assert.deepEqual(T.evaluateTreeHead(null, head(7, "2026-11-27T11:00:00Z"), [], logKey, { now }), { status: "rejected", reason: "future" });
  const entry = entries(20)[5];
  assert.ok(T.verifyEntryInclusion({ entry, index: 5, head: h20, path: t.inclusionProof(5) }));
  assert.equal(T.verifyEntryInclusion({ entry: entry.replace("u5", "u6"), index: 5, head: h20, path: t.inclusionProof(5) }), false);
});
