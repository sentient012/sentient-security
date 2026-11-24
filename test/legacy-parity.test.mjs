/*
 * Byte-for-byte parity with the deployed Sentient implementations.
 * test/vectors/legacy-vectors.json was produced by running the SAME scenarios
 * (test/scenarios.mjs) against the unmodified app / terminal sources (see
 * tools/capture-legacy-vectors.cjs). Here they run against this package,
 * imported through its public export map.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import * as hybridV1 from "@sentient012/security/hybrid-v1";
import * as business from "@sentient012/security/business";
import * as group from "@sentient012/security/group";
import * as keyring from "@sentient012/security/recovery/keyring";
import * as recovery from "@sentient012/security/recovery";
import * as passkey from "@sentient012/security/recovery/passkey";
import * as preview from "@sentient012/security/notification-preview";
import * as call from "@sentient012/security/call";
import * as frame from "@sentient012/security/call/frame-web";
import { deterministicRandom } from "@sentient012/security/testing";

import * as S from "./scenarios.mjs";

const legacy = JSON.parse(readFileSync(new URL("./vectors/legacy-vectors.json", import.meta.url), "utf8"));
const L = legacy.vectors;

const libraryHybrid = {
  encrypt: async (p) => hybridV1.encryptPayload({ plaintext: p.plaintext, threadId: p.threadId, senderUserId: p.senderUserId, receiverUserId: p.receiverUserId, recipients: p.recipients }),
  decrypt: async (payload, device) => {
    const keys = hybridV1.deviceKeysFromSecrets(device.x25519PrivateKey, device.mlKemSeed);
    const deviceKeyId = hybridV1.deviceKeyIdFor(device.credentialId);
    const envelope = payload.envelopes.find((e) => e.deviceKeyId === deviceKeyId);
    return hybridV1.decryptEnvelope(payload, envelope, { deviceKeyId, x25519PrivateKey: device.x25519PrivateKey, mlKemSecretKey: keys.mlKemSecretKey });
  },
};
const impl = {
  hybrid: libraryHybrid,
  business,
  group,
  keyring,
  recovery,
  passkey,
  preview,
  frame,
  call: {
    Handshake: call.CallPqcHandshake,
    extractDtlsFingerprints: call.extractDtlsFingerprints,
    makeIdentity: async (credentialId, edSeed, mlDsaSeed) => call.signingIdentityFromSeeds(credentialId, edSeed, mlDsaSeed),
  },
};

async function run(name, fn) {
  const rand = deterministicRandom(`${S.SCENARIO_SEED} / ${name}`);
  const value = await S.withDeterminism(rand, null, () => fn(rand));
  return { value, randomBytesConsumed: rand.consumed };
}
// Round-trip through JSON exactly as the capture did.
const json = (v) => JSON.parse(JSON.stringify(v));

test("vectors were captured from a clean, identified source tree", () => {
  for (const repo of Object.values(legacy.sources)) {
    assert.match(repo.commit, /^[0-9a-f]{40}$/);
    assert.equal(repo.dirty, "clean");
  }
});

test("sentient-hybrid-v1: identical envelopes, transcripts and plaintexts", async () => {
  assert.deepEqual(json(await run("hybrid", (rand) => S.hybridScenario(impl, rand))), L.hybrid);
});

test("business protocol: identical wraps, signatures, messages, attachments, scanner and org-key boxes", async () => {
  assert.deepEqual(json(await run("business", () => S.businessScenario(impl))), L.business);
});

test("group protocol: identical wraps, key links and messages", async () => {
  assert.deepEqual(json(await run("group", () => S.groupScenario(impl))), L.group);
});

test("notification preview opens deployed direct and group payloads identically", () => {
  assert.deepEqual(json({ value: S.previewScenario(impl, L.hybrid.value, L.group.value) }), L.preview);
});

test("recovery formats: keyring v1, recovery v2, recovery key codec, passkey wrapper", async () => {
  assert.deepEqual(json(await run("recovery", (rand) => S.recoveryScenario(impl, rand))), L.recovery);
});

test("call handshake: identical signed hello/accept/confirm/confirmed and media keys", async () => {
  assert.deepEqual(json(await run("call", (rand) => S.callScenario(impl, rand))), L.call);
});

test("browser frame crypto: identical sealed frames", async () => {
  assert.deepEqual(json(await run("frame", (rand) => S.frameScenario(impl, rand))), L.frame);
});

test("library decrypts every legacy hybrid-v1 vector without the deterministic stream", () => {
  const devices = L.hybrid.value.devices;
  for (const m of L.hybrid.value.messages) {
    for (const [credentialId, d] of Object.entries(devices)) {
      const x = Uint8Array.from(Buffer.from(d.x25519PrivateKey, "base64"));
      const seed = Uint8Array.from(Buffer.from(d.mlKemSeed, "base64"));
      const keys = hybridV1.deviceKeysFromSecrets(x, seed);
      const envelope = m.payload.envelopes.find((e) => e.deviceKeyId === `${credentialId}:hybrid-v1`);
      assert.equal(hybridV1.decryptEnvelope(m.payload, envelope, { deviceKeyId: envelope.deviceKeyId, x25519PrivateKey: x, mlKemSecretKey: keys.mlKemSecretKey }), m.decrypted[credentialId]);
    }
  }
});
