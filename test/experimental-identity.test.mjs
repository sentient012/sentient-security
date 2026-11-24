/*
 * EXPERIMENTAL module tests (not part of the published package).
 * Built separately: tsc -p tsconfig.experimental.json
 */
import test from "node:test";
import assert from "node:assert/strict";

import * as V from "../build-experimental/experimental/identity-verification.js";

const alice = { userId: "aaaa", keys: [{ kind: "x25519", publicKey: "AAA=" }, { kind: "mlkem", publicKey: "BBB=" }] };
const bob = { userId: "bbbb", keys: [{ kind: "x25519", publicKey: "CCC=" }] };

test("comparison code is symmetric, 60 digits, order- and duplicate-insensitive", () => {
  const ab = V.comparisonCode(alice, bob);
  assert.match(ab, /^\d{60}$/);
  assert.equal(V.comparisonCode(bob, alice), ab);
  const shuffled = { userId: "aaaa", keys: [alice.keys[1], alice.keys[0], alice.keys[0]] };
  assert.equal(V.comparisonCode(shuffled, bob), ab);
  assert.equal(V.formatComparisonCode(ab).split(" ").length, 12);
});

test("any key change, added device, or different account changes the code", () => {
  const ab = V.comparisonCode(alice, bob);
  assert.notEqual(V.comparisonCode({ ...alice, keys: [...alice.keys, { kind: "x25519", publicKey: "DDD=" }] }, bob), ab);
  assert.notEqual(V.comparisonCode({ ...alice, keys: [alice.keys[0]] }, bob), ab);
  assert.notEqual(V.comparisonCode({ userId: "aaab", keys: alice.keys }, bob), ab);
  assert.notEqual(V.comparisonCode(alice, { ...bob, keys: [{ kind: "mlkem", publicKey: "CCC=" }] }), ab, "kind is bound");
});

test("length prefixes prevent field-boundary ambiguity", () => {
  const a1 = { userId: "u", keys: [{ kind: "k", publicKey: "ab" }] };
  const a2 = { userId: "u", keys: [{ kind: "k", publicKey: "a" }, { kind: "k", publicKey: "b" }] };
  assert.notDeepEqual(V.accountDigest(a1, 2), V.accountDigest(a2, 2));
});

test("invalid inputs are rejected", () => {
  assert.throws(() => V.comparisonCode(alice, alice));
  assert.throws(() => V.comparisonCode({ userId: "x", keys: [] }, bob));
  assert.throws(() => V.comparisonCode({ userId: "x", keys: [{ kind: "a:b", publicKey: "Z" }] }, bob));
});

test("key pins: first seen, unchanged keeps verification, change clears it and reports the diff", () => {
  const first = V.checkKeyPin(null, alice);
  assert.equal(first.status, "first_seen");
  const verified = V.markVerified(first.next);
  const same = V.checkKeyPin(verified, { ...alice, keys: [...alice.keys].reverse() });
  assert.equal(same.status, "unchanged");
  assert.equal(same.next.verified, true);
  const changed = V.checkKeyPin(verified, { ...alice, keys: [alice.keys[0], { kind: "mlkem", publicKey: "EVIL=" }] });
  assert.equal(changed.status, "changed");
  assert.deepEqual(changed.added, ["mlkem:EVIL="]);
  assert.deepEqual(changed.removed, ["mlkem:BBB="]);
  assert.equal(changed.wasVerified, true);
  assert.equal(changed.next.verified, false);
  assert.throws(() => V.checkKeyPin(verified, bob));
});

test("frozen vector (detects accidental changes to the experimental encoding)", () => {
  assert.equal(V.comparisonCode(alice, bob, 3).length, 60);
  // Recorded from this implementation; NOT an interoperability guarantee (v0, experimental).
  assert.equal(V.comparisonCode(alice, bob), "906206194472173650176756704973006204349225313281373683090025");
});
