/*
 * recovery/keys (sentient-recovery-v2): moved from the Sentient app in 0.3.0.
 * Fixed vectors: the app (lib/recovery-keys.ts, 4.2.0) and the website's
 * WebCrypto copy must derive the same authToken for the same two keys.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";

import * as K from "@sentient012/security/recovery/keys";

const K1 = "01234567890123456789", K2 = "98765432109876543210";

test("keys are 20 uniform digits; formatting and parsing round-trip, including other digit scripts", () => {
  const [a, b] = K.generateRecoveryKeyPair();
  assert.match(a, /^\d{20}$/);
  assert.match(b, /^\d{20}$/);
  assert.notEqual(a, b);
  assert.equal(K.formatRecoveryKey(K1), "0123-45678-90123-456789");
  assert.equal(K.parseRecoveryKey("0123 45678-90123.456789"), K1);
  assert.equal(K.parseRecoveryKey("٠١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦٧٨٩"), K1);
  assert.equal(K.parseRecoveryKey("0123456789012345678"), null);
  assert.equal(K.parseRecoveryKey("0123456789012345678a"), null);
  // A source that only ever returns values above the rejection limit fails instead of biasing.
  assert.throws(() => K.generateRecoveryKey(() => new Uint8Array(9).fill(255)), /rng/);
});

test("derivation needs both keys and matches the HKDF definition", () => {
  const m = K.deriveRecoveryMaterial(K1, K2);
  assert.match(m.authToken, /^[0-9a-f]{64}$/);
  assert.equal(m.wrapKey.length, 32);
  assert.notEqual(K.deriveRecoveryMaterial(K2, K1).authToken, m.authToken, "order matters");
  const ikm = Buffer.from(`sentient-recovery-v2|${K1}|${K2}`);
  const expected = Buffer.from(hkdf32(ikm, Buffer.from("sentient-recovery-v2/salt"), Buffer.from("sentient-recovery-v2/auth"))).toString("hex");
  assert.equal(m.authToken, expected);
  assert.equal(K.authTokenHash(m.authToken), createHash("sha256").update(Buffer.from(m.authToken, "hex")).digest("hex"));
});

/** RFC 5869 HKDF-SHA-256, one 32-byte block, independent of @noble. */
function hkdf32(ikm, salt, info) {
  const prk = createHmac("sha256", salt).update(ikm).digest();
  return createHmac("sha256", prk).update(Buffer.concat([info, Buffer.from([1])])).digest();
}

test("backup key wrap and backup seal bind the account (and the version)", () => {
  const { wrapKey } = K.deriveRecoveryMaterial(K1, K2);
  const backupKey = new Uint8Array(32).fill(7);
  const wrapped = K.wrapBackupKey(wrapKey, backupKey, "user-a");
  assert.deepEqual(K.unwrapBackupKey(wrapKey, wrapped, "user-a"), backupKey);
  assert.throws(() => K.unwrapBackupKey(wrapKey, wrapped, "user-b"), /unwrap/);
  assert.throws(() => K.unwrapBackupKey(K.deriveRecoveryMaterial(K2, K1).wrapKey, wrapped, "user-a"), /unwrap/);
  const sealed = K.sealBackup(backupKey, "user-a", 3, { messages: [{ id: "m", text: "hi" }] });
  assert.equal(K.openBackup(backupKey, "user-a", sealed).snapshot.messages[0].text, "hi");
  assert.throws(() => K.openBackup(backupKey, "user-b", sealed), /backup_integrity/);
  const moved = JSON.stringify({ ...JSON.parse(sealed), version: 4 });
  assert.throws(() => K.openBackup(backupKey, "user-a", moved), /backup_integrity/);
});
