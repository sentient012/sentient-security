/*
 * Differential scenarios. Each scenario runs against an "impl" object and
 * returns plain JSON. tools/capture-legacy-vectors.cjs runs them against the
 * UNMODIFIED Sentient app / Business Terminal source and stores the result in
 * test/vectors/legacy-vectors.json; test/legacy-parity.test.mjs runs them
 * against this library and requires byte-identical output.
 *
 * Randomness: every scenario runs inside withDeterminism(), which routes
 * crypto.getRandomValues (used by @noble/*) and the impl's own RNG hook
 * through ONE public, test-only stream, and fixes the clock. Deployed code
 * consumes randomness in a fixed order, so identical streams give identical
 * bytes only if the implementation is byte-compatible.
 *
 * All keys here are derived from public test seeds. TEST ONLY.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { base64 } from "@scure/base";

export const FIXED_TIME_MS = Date.parse("2026-11-23T12:00:00.000Z");
const b64 = (u8) => base64.encode(u8);
const ub64 = (s) => base64.decode(s);

const RealDate = Date;
export async function withDeterminism(rand, setImplRandom, fn) {
  const cryptoObj = globalThis.crypto;
  const original = cryptoObj.getRandomValues.bind(cryptoObj);
  let clock = FIXED_TIME_MS;
  class FixedDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) super(clock);
      else super(...args);
    }
    static now() {
      return clock;
    }
  }
  FixedDate.parse = RealDate.parse;
  FixedDate.UTC = RealDate.UTC;
  Object.defineProperty(cryptoObj, "getRandomValues", {
    configurable: true,
    writable: true,
    value: (array) => {
      const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      view.set(rand(view.length));
      return array;
    },
  });
  globalThis.Date = FixedDate;
  setImplRandom?.(rand);
  try {
    return await fn({ advance: (ms) => (clock += ms) });
  } finally {
    globalThis.Date = RealDate;
    Object.defineProperty(cryptoObj, "getRandomValues", { configurable: true, writable: true, value: original });
    setImplRandom?.(null);
  }
}

// ---------------------------------------------------------------------------
// sentient-hybrid-v1
// impl.hybrid: {
//   encrypt({ plaintext, threadId, senderUserId, receiverUserId, senderDevice, recipients }) -> payload
//   decrypt(payload, device) -> string   (device = { userId, credentialId, x25519PrivateKey, mlKemSeed })
// }
// ---------------------------------------------------------------------------
function hybridDevice(rand, userId, credentialId) {
  const x25519PrivateKey = rand(32);
  const mlKemSeed = rand(64);
  const kem = ml_kem768.keygen(mlKemSeed);
  return {
    userId,
    credentialId,
    x25519PrivateKey,
    mlKemSeed,
    bundle: {
      id: `${credentialId}:hybrid-v1`,
      user_id: userId,
      credential_id: credentialId,
      x25519_public_key: b64(x25519.getPublicKey(x25519PrivateKey)),
      ml_kem_public_key: b64(kem.publicKey),
      is_active: true,
      created_at: "2026-11-01T00:00:00.000Z",
    },
  };
}

const ALICE = "11111111-1111-4111-8111-111111111111";
const BOB = "22222222-2222-4222-8222-222222222222";
const CAROL = "33333333-3333-4333-8333-333333333333";
const THREAD = "44444444-4444-4444-8444-444444444444";
const GROUP = "55555555-5555-4555-8555-555555555555";
const ORG = "66666666-6666-4666-8666-666666666666";
const INTERACTION = "77777777-7777-4777-8777-777777777777";

export const HYBRID_PLAINTEXTS = [
  "hello",
  "",
  "Ünïcödé — 日本語 — emoji 👍🏽🇺🇳",
  "x".repeat(4099),
  '{"messageType":"sentient-attachment-v1","attachmentId":"a1","fileName":"f.jpg","mimeType":"image/jpeg"}',
  "lone surrogate \ud800 replaced by U+FFFD on encode",
];

export async function hybridScenario(impl, rand) {
  const aliceA = hybridDevice(rand, ALICE, "cred_alice_a");
  const aliceB = hybridDevice(rand, ALICE, "cred_alice_b");
  const bob = hybridDevice(rand, BOB, "cred_bob_1");
  const out = { devices: {}, messages: [] };
  for (const d of [aliceA, aliceB, bob]) out.devices[d.credentialId] = { x25519PrivateKey: b64(d.x25519PrivateKey), mlKemSeed: b64(d.mlKemSeed), bundle: d.bundle };
  for (const plaintext of HYBRID_PLAINTEXTS) {
    const payload = await impl.hybrid.encrypt({
      plaintext,
      threadId: THREAD,
      senderUserId: ALICE,
      receiverUserId: BOB,
      senderDevice: aliceA,
      recipients: [aliceA.bundle, aliceB.bundle, bob.bundle],
    });
    const decrypted = {};
    for (const d of [aliceA, aliceB, bob]) decrypted[d.credentialId] = await impl.hybrid.decrypt(payload, d);
    out.messages.push({ plaintext, payload, decrypted });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Business protocol (same API in both impls: impl.business = core module,
// impl.businessKeys = conversation-keys module)
// ---------------------------------------------------------------------------
function businessDevice(core, kind, keyId) {
  const seeds = core.newDeviceSeeds();
  const signing = core.signingKeysFromSeeds(seeds);
  const kem = core.kemKeysFromSeeds(seeds);
  return {
    kind,
    keyId,
    seeds,
    signing,
    kem,
    publicSigning: { ed25519_public_key: b64(signing.ed25519PublicKey), ml_dsa_public_key: b64(signing.mlDsaPublicKey) },
    target: { kind, keyId, x25519PublicKey: kem.x25519PublicKey, mlKemPublicKey: kem.mlKemPublicKey },
  };
}

export async function businessScenario(impl) {
  const core = impl.business;
  const phone = businessDevice(core, "consumer_device", "cred_bob_1:biz-v1");
  const terminal = businessDevice(core, "terminal_device", "terminal-key-1");
  const createdAt = new Date().toISOString();
  const ck = core.newConversationKey();
  const commitment = core.conversationKeyCommitment(ck, { interactionId: INTERACTION, organizationId: ORG, epoch: 1 });
  const wrap = core.wrapConversationKey({
    conversationKey: ck, interactionId: INTERACTION, organizationId: ORG, epoch: 1,
    recipient: phone.target, wrapper: { kind: "terminal_device", keyId: terminal.keyId, signingKeys: terminal.signing }, createdAt,
  });
  const opened = core.unwrapConversationKey({
    wrap, recipientPrivate: phone.kem,
    expected: { interactionId: INTERACTION, organizationId: ORG, epoch: 1, recipientKind: "consumer_device", recipientKeyId: phone.keyId, wrapperKeyId: terminal.keyId },
    wrapperPublicKeys: terminal.publicSigning,
  });
  const header = { interactionId: INTERACTION, organizationId: ORG, epoch: 1, messageId: "m-1", senderType: "business", senderKind: "terminal_device", senderKeyId: terminal.keyId, senderId: "agent-1", createdAt };
  const message = core.encryptBusinessMessage({ conversationKey: ck, header, content: { kind: "text", text: "Your order shipped 📦" }, signingKeys: terminal.signing });
  const decrypted = core.decryptBusinessMessage({ payload: message, conversationKey: opened, senderPublicKeys: terminal.publicSigning, expected: { interactionId: INTERACTION, messageId: "m-1", senderKeyId: terminal.keyId } });
  const file = core.encryptAttachmentBytes(new Uint8Array([1, 2, 3, 4, 5, 250]));
  const reopened = core.decryptAttachmentBytes({ ciphertext: file.ciphertext, fileKey: file.fileKey, nonce: file.nonce, contentHash: file.contentHash });
  const scanner = businessDevice(core, "scanner", "scanner-1");
  const scanBox = core.sealForScanner({ fileKey: file.fileKey, nonce: file.nonce, uploadId: "u-1", scanner: { keyId: scanner.keyId, x25519PublicKey: scanner.kem.x25519PublicKey, mlKemPublicKey: scanner.kem.mlKemPublicKey }, expiresAt: "2026-11-23T12:10:00.000Z" });
  const scanOpen = core.openScannerSeal({ box: scanBox, scannerPrivate: scanner.kem, now: Date.now() });
  const orgSeeds = core.newOrgAccessKeySeeds();
  const orgKem = core.kemKeysFromSeeds(orgSeeds);
  const orgBox = core.sealOrgAccessKey({ seeds: orgSeeds, organizationId: ORG, orgKeyId: "org-key-1", generation: 1, recipientDevice: terminal.target, distributor: { keyId: terminal.keyId, signingKeys: terminal.signing }, createdAt });
  const orgOpen = core.openOrgAccessKey({ box: orgBox, expected: { organizationId: ORG, orgKeyId: "org-key-1" }, devicePrivate: terminal.kem, distributorPublicKeys: terminal.publicSigning, orgPublicKeys: { x25519_public_key: b64(orgKem.x25519PublicKey), ml_kem_public_key: b64(orgKem.mlKemPublicKey) } });
  return {
    phone: phone.publicSigning, terminal: terminal.publicSigning,
    ck: b64(ck), commitment, wrap, opened: b64(opened), message, decrypted,
    file: { ciphertext: b64(file.ciphertext), fileKey: b64(file.fileKey), nonce: b64(file.nonce), contentHash: file.contentHash, reopened: b64(reopened) },
    scanBox, scanOpen: { fileKey: b64(scanOpen.fileKey), nonce: b64(scanOpen.nonce) },
    orgBox, orgOpen: { x25519PublicKey: b64(orgOpen.x25519PublicKey), mlKemPublicKeyLength: orgOpen.mlKemPublicKey.length },
    canonical: core.canonicalize({ b: [1, "x", null, true], a: { z: 1, y: undefined }, c: 1.5 }),
  };
}

// ---------------------------------------------------------------------------
// Group protocol (impl.group = core module)
// ---------------------------------------------------------------------------
export async function groupScenario(impl) {
  const core = impl.group;
  const biz = impl.business;
  const mk = (userId, keyId) => {
    const d = businessDevice(biz, "member", keyId);
    return { ...d, userId };
  };
  const alice = mk(ALICE, "alice-sign-1");
  const bob = mk(BOB, "bob-sign-1");
  const createdAt = new Date().toISOString();
  const gk1 = core.newGroupKey();
  const gk2 = core.newGroupKey();
  const wrap = core.wrapGroupKey({ groupKey: gk2, groupId: GROUP, epoch: 2, recipient: { userId: BOB, keyId: "bob-kem-1", x25519PublicKey: bob.kem.x25519PublicKey, mlKemPublicKey: bob.kem.mlKemPublicKey }, wrapper: { userId: ALICE, keyId: alice.keyId, signingKeys: alice.signing }, createdAt });
  const opened = core.unwrapGroupKey({ wrap, recipientPrivate: bob.kem, expected: { groupId: GROUP, epoch: 2, recipientKeyId: "bob-kem-1", recipientUserId: BOB, wrapperKeyId: alice.keyId }, wrapperPublicKeys: alice.publicSigning });
  const link = core.sealKeyLink({ olderKey: gk1, newerKey: gk2, groupId: GROUP, olderEpoch: 1, wrapper: { userId: ALICE, keyId: alice.keyId, signingKeys: alice.signing }, createdAt });
  const older = core.openKeyLink({ link, newerKey: opened, expected: { groupId: GROUP, epoch: 1, newerEpoch: 2 }, wrapperPublicKeys: alice.publicSigning, expectedCommitment: core.groupKeyCommitment(gk1, { groupId: GROUP, epoch: 1 }) });
  const header = { groupId: GROUP, epoch: 2, messageId: "g-1", senderId: ALICE, senderKeyId: alice.keyId, createdAt };
  const message = core.encryptGroupMessage({ groupKey: gk2, header, content: { kind: "text", text: "group hello 👋" }, signingKeys: alice.signing });
  const decrypted = core.decryptGroupMessage({ payload: message, groupKey: opened, senderPublicKeys: alice.publicSigning, expected: { groupId: GROUP, epoch: 2, messageId: "g-1", senderId: ALICE } });
  return { gk1: b64(gk1), gk2: b64(gk2), wrap, opened: b64(opened), link, older: b64(older), message, decrypted };
}

// ---------------------------------------------------------------------------
// Notification preview (impl.preview = module), run on the hybrid and group outputs
// ---------------------------------------------------------------------------
export function previewScenario(impl, hybrid, group) {
  const bob = hybrid.devices.cred_bob_1;
  const kem = ml_kem768.keygen(ub64(bob.mlKemSeed));
  const direct = hybrid.messages.map((m) => {
    const onlyBob = { ...m.payload, envelopes: m.payload.envelopes.filter((e) => e.userId === m.payload.receiverUserId) };
    const text = impl.preview.openDirectMessage(onlyBob, { x25519PrivateKey: bob.x25519PrivateKey, mlKemSecretKey: kem.secretKey });
    return { text, described: impl.preview.describeDirect(text) };
  });
  const { signature: _sig, ...unsigned } = group.message;
  const groupContent = impl.preview.openGroupMessage(unsigned, group.gk2, { groupId: unsigned.groupId, messageId: unsigned.messageId });
  return { direct, group: groupContent, describedGroup: impl.preview.describeGroup(groupContent) };
}

// ---------------------------------------------------------------------------
// Recovery formats (impl.keyring, impl.recovery, impl.passkey = modules)
// ---------------------------------------------------------------------------
export function recoveryScenario(impl, rand) {
  const entries = [0, 1].map((i) => ({ credentialId: `cred_${i}`, deviceKeyId: `cred_${i}:hybrid-v1`, x25519PrivateKey: rand(32), mlKemSeed: rand(64) }));
  const share = rand(32);
  const v1 = impl.keyring.encryptKeyring({ userId: ALICE, entries, share, randomBytes: rand });
  const v1Back = impl.keyring.decryptKeyring({ fileText: v1, share, userId: ALICE });
  const clientShare = impl.recovery.newClientShare(rand);
  const v2 = impl.recovery.encryptRecoveryObject({ userId: ALICE, entries, serverShare: share, clientShare, generation: 3, randomBytes: rand });
  const v2Back = impl.recovery.decryptRecoveryObject({ text: v2.text, userId: ALICE, serverShare: share, clientShare, expectedGeneration: 3 });
  const recoveryKey = impl.recovery.formatRecoveryKey(clientShare);
  const parsed = impl.recovery.parseRecoveryKey(recoveryKey.toLowerCase().replace(/-/g, " "));
  const prf = rand(32);
  const wrapper = impl.passkey.wrapClientShare({ userId: ALICE, credentialId: "passkey-cred-1", clientShare, prfOutput: prf });
  const unwrapped = impl.passkey.unwrapClientShare({ userId: ALICE, credentialId: "passkey-cred-1", wrapper, prfOutput: prf });
  const ser = (list) => list.map((e) => ({ ...e, x25519PrivateKey: b64(e.x25519PrivateKey), mlKemSeed: b64(e.mlKemSeed) }));
  return { v1, v1Back: ser(v1Back), v2, v2Back: ser(v2Back), shareId: impl.recovery.shareIdFor(clientShare), recoveryKey, parsed: b64(parsed), wrapper, unwrapped: b64(unwrapped) };
}

// ---------------------------------------------------------------------------
// Call handshake (impl.call: { Handshake, makeIdentity(credentialId, edSeed, mlDsaSeed) -> identity, extractDtlsFingerprints })
// ---------------------------------------------------------------------------
export async function callScenario(impl, rand) {
  const callerId = await impl.call.makeIdentity("cred_alice_a", rand(32), rand(32));
  const calleeId = await impl.call.makeIdentity("cred_bob_1", rand(32), rand(32));
  const bundleOf = (id, userId, attested) => ({
    id: id.deviceKeyId, user_id: userId, credential_id: id.credentialId, protocol_version: "sentient-call-hybrid-v1",
    ed25519_public_key: b64(id.ed25519PublicKey), ml_dsa_public_key: b64(id.mlDsaPublicKey), is_active: true, attestation_verified: attested,
  });
  const bundles = new Map([[callerId.deviceKeyId, bundleOf(callerId, ALICE, true)], [calleeId.deviceKeyId, bundleOf(calleeId, BOB, false)]]);
  const sdpA = "v=0\r\na=fingerprint:sha-256 AA:BB:CC\r\n";
  const sdpB = "v=0\r\na=fingerprint:SHA-256 11:22:33\r\na=fingerprint:sha-256 11:22:33\r\n";
  const make = (role, identity) => new impl.call.Handshake({
    role, callId: "call-1", callerUserId: ALICE, calleeUserId: BOB, localIdentity: identity,
    getPeerBundle: async (id) => bundles.get(id) ?? null,
    localDtlsFingerprints: () => impl.call.extractDtlsFingerprints(role === "caller" ? sdpA : sdpB),
  });
  const caller = make("caller", callerId);
  const callee = make("callee", calleeId);
  const hello = await caller.buildHello();
  const accept = await callee.handleHelloBuildAccept(hello);
  const confirm = await caller.handleAcceptBuildConfirm(accept);
  const confirmed = await callee.handleConfirmBuildConfirmed(confirm);
  const ok = await caller.handleConfirmed(confirmed);
  const strip = (s) => ({ ...s });
  return {
    hello, accept, confirm, confirmed, ok,
    callerKey: b64(caller.getResult().mediaBaseKey), calleeKey: b64(callee.getResult().mediaBaseKey),
    callerState: strip(caller.state), calleeState: strip(callee.state),
    fingerprints: impl.call.extractDtlsFingerprints(sdpB),
  };
}

// ---------------------------------------------------------------------------
// Browser frame crypto (impl.frame = module); fixed IVs
// ---------------------------------------------------------------------------
export async function frameScenario(impl, rand) {
  const base = rand(32);
  const key = await impl.frame.deriveFrameKey(base);
  const frames = [];
  for (const size of [1, 2, 40, 961]) {
    const data = rand(size);
    const iv = rand(12);
    const sealed = new Uint8Array(await impl.frame.encryptFrame(key, data, { iv }));
    const opened = new Uint8Array(await impl.frame.decryptFrame(key, sealed));
    frames.push({ data: b64(data), iv: b64(iv), sealed: b64(sealed), opened: b64(opened), looksSealed: impl.frame.looksLikeSealedFrame(sealed) });
  }
  return { base: b64(base), frames };
}

export const SCENARIO_SEED = "TEST ONLY sentient-security legacy parity v1";
