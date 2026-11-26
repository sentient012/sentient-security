/*
 * EXPERIMENTAL - NOT REVIEWED - NOT USED BY ANY SENTIENT CLIENT.
 * Protocol id: "sentient-pqxdh-v0-experimental".
 *
 * Authenticated initial key agreement following the structure of PQXDH
 * (Signal specification, revision 3, 2023-05-24; public domain):
 *     DH1 = DH(IK_A, SPK_B)   DH2 = DH(EK_A, IK_B)   DH3 = DH(EK_A, SPK_B)
 *     DH4 = DH(EK_A, OPK_B)   (only if a one-time prekey was available)
 *     (CT, SS) = ML-KEM-768.Encaps(PQPK_B)   (one-time PQ prekey preferred, else last-resort)
 *     SK = HKDF-SHA-256(salt = 0^32, ikm = 0xFF^32 || DH1 || DH2 || DH3 [|| DH4] || SS,
 *                       info = "Sentient_CURVE25519_SHA-256_MLKEM768_PQXDH-v0", 64)
 *     SK splits into SK_ec (Double Ratchet root) and SK_pq (post-quantum epoch ratchet root).
 *
 * DEVIATIONS from the PQXDH specification, deliberately and documented:
 *   1. Prekeys are signed with Sentient's existing HYBRID identity signature
 *      (Ed25519 + ML-DSA-65, both required) instead of XEdDSA with the DH
 *      identity key. The DH identity key IK (X25519) is a separate key, bound
 *      to the signing identity by a hybrid signature in the bundle. This avoids
 *      implementing XEdDSA and gives prekey authentication that also resists a
 *      future quantum forger.
 *   2. The initiator SIGNS the initial message transcript with its hybrid
 *      identity key. PQXDH authenticates the initiator only implicitly (DH1),
 *      which a quantum adversary could defeat. The cost is deniability: the
 *      responder can prove to others that the initiator started this session.
 *   3. The associated data binds both full identities (user id, device id,
 *      DH identity key, signing keys) and the protocol id, not just IK_A||IK_B.
 *
 * WHAT THIS DOES NOT FIX BY ITSELF: identity keys still come from Sentient's
 * server. A server that substitutes a whole identity (not just a prekey) is
 * detected only by identity verification (identity-verification.ts) and key
 * pinning (device-list.ts).
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { canonicalBytes, fromB64, toB64 } from "../encoding/index.js";
import { signHybrid, signingKeysFromSeeds, verifyHybrid } from "../business/core.js";
import { RATCHET_PROTOCOL, decrypt, encrypt, initInitiator, initResponder, type RatchetMessage, type RatchetState } from "./ratchet.js";

export const PQXDH_PROTOCOL = "sentient-pqxdh-v0-experimental" as const;
export const EXPERIMENTAL = true as const;
const KDF_INFO = utf8ToBytes("Sentient_CURVE25519_SHA-256_MLKEM768_PQXDH-v0");
const SIGN_CONTEXT = `${PQXDH_PROTOCOL}/prekey`;
const INIT_CONTEXT = `${PQXDH_PROTOCOL}/initial-message`;
const IDENTITY_CONTEXT = `${PQXDH_PROTOCOL}/identity-binding`;

export class PqxdhError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = "PqxdhError";
    this.code = code;
  }
}

type RandomSource = (length: number) => Uint8Array;
type SigningKeys = ReturnType<typeof signingKeysFromSeeds>;
type HybridSig = { ed25519: string; mlDsa: string };

/** A device's long-term identity: signing seeds plus an X25519 DH identity key. Stored by the app (secure storage). */
export type DeviceIdentitySecrets = { userId: string; deviceId: string; ed25519Seed: string; mlDsaSeed: string; ikPriv: string };

/** Public identity as published and as pinned by peers. */
export type PublicIdentity = {
  userId: string;
  deviceId: string;
  ik: string;
  ed25519_public_key: string;
  ml_dsa_public_key: string;
  /** Hybrid signature binding ik to the signing keys, user and device. */
  binding: HybridSig;
};

export function newDeviceIdentity(userId: string, deviceId: string, rand: RandomSource = randomBytes): DeviceIdentitySecrets {
  return { userId, deviceId, ed25519Seed: toB64(rand(32)), mlDsaSeed: toB64(rand(32)), ikPriv: toB64(rand(32)) };
}

export function signingKeysOf(id: DeviceIdentitySecrets): SigningKeys {
  return signingKeysFromSeeds({ ed25519Seed: fromB64(id.ed25519Seed), mlDsaSeed: fromB64(id.mlDsaSeed) });
}

export function publicIdentity(id: DeviceIdentitySecrets): PublicIdentity {
  const keys = signingKeysOf(id);
  const fields = {
    userId: id.userId,
    deviceId: id.deviceId,
    ik: toB64(x25519.getPublicKey(fromB64(id.ikPriv))),
    ed25519_public_key: toB64(keys.ed25519PublicKey),
    ml_dsa_public_key: toB64(keys.mlDsaPublicKey),
  };
  return { ...fields, binding: signHybrid(IDENTITY_CONTEXT, fields, keys) };
}

/** Self-consistency of a published identity (its DH key is bound to its signing keys). It does NOT say the identity is genuine; see identity-verification.ts. */
export function verifyPublicIdentity(id: PublicIdentity): boolean {
  const { binding, ...fields } = id;
  return !!binding && verifyHybrid(IDENTITY_CONTEXT, fields, binding, id).both;
}

// --- Prekeys -------------------------------------------------------------------
export type SignedPrekey = { kind: "x25519-signed" | "x25519-one-time" | "mlkem768-signed" | "mlkem768-one-time"; id: string; pub: string; signature: HybridSig };
export type PrekeyBundle = {
  v: typeof PQXDH_PROTOCOL;
  identity: PublicIdentity;
  /** Protocols this device accepts, signed (downgrade protection). */
  capabilities: { protocols: string[]; signature: HybridSig };
  spk: SignedPrekey;
  pqspk: SignedPrekey;
  opk?: SignedPrekey;
  pqopk?: SignedPrekey;
};

/** Private prekey material the device keeps. One-time entries are deleted after use. */
export type PrekeyStore = {
  spk: { id: string; priv: string; createdAt?: string };
  pqspk: { id: string; dk: string; createdAt?: string };
  opks: Record<string, string>;
  pqopks: Record<string, string>;
  /**
   * "<signed prekey id>|<hash>" of initial messages already accepted with only
   * last-resort prekeys (replay protection). Entries are dropped together with
   * their signed prekey (audit E-8), so a replay can never outlive the key it needs.
   */
  seenInitial: string[];
  /**
   * Signed prekeys replaced by rotateSignedPrekeys, kept for a grace period so
   * initial messages already in flight still open (audit E-3).
   */
  retired?: { spks: { id: string; priv: string; retiredAt: string }[]; pqspks: { id: string; dk: string; retiredAt: string }[] };
};
const MAX_SEEN_INITIAL = 10000;
/** Default grace period for a rotated signed prekey: initial messages addressed to it are accepted this long. */
export const SIGNED_PREKEY_GRACE_MS = 14 * 24 * 60 * 60 * 1000;
/** Recommended rotation interval for signed prekeys (the app schedules rotateSignedPrekeys). */
export const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_ONE_TIME_PREKEYS = 200;
/** Default signed capabilities: the whole session suite (audit E-1). */
export const DEFAULT_PROTOCOLS: readonly string[] = [PQXDH_PROTOCOL, RATCHET_PROTOCOL];

function signPrekey(identity: DeviceIdentitySecrets, kind: SignedPrekey["kind"], id: string, pub: Uint8Array): SignedPrekey {
  const fields = { v: PQXDH_PROTOCOL, kind, id, pub: toB64(pub), userId: identity.userId, deviceId: identity.deviceId };
  return { kind, id, pub: toB64(pub), signature: signHybrid(SIGN_CONTEXT, fields, signingKeysOf(identity)) };
}

function verifyPrekey(identity: PublicIdentity, prekey: SignedPrekey | undefined, kind: SignedPrekey["kind"]): boolean {
  if (!prekey || prekey.kind !== kind) return false;
  const fields = { v: PQXDH_PROTOCOL, kind, id: prekey.id, pub: prekey.pub, userId: identity.userId, deviceId: identity.deviceId };
  return verifyHybrid(SIGN_CONTEXT, fields, prekey.signature, identity).both;
}

/** Creates a device's prekeys. Returns the private store and a function to publish bundles (one one-time key of each kind per bundle). */
export function generatePrekeys(identity: DeviceIdentitySecrets, opts: { oneTimeCount?: number; protocols?: string[]; rand?: RandomSource } = {}) {
  const rand = opts.rand ?? randomBytes;
  const count = opts.oneTimeCount ?? 20;
  const spkPriv = rand(32);
  const pqspk = ml_kem768.keygen(rand(64));
  const store: PrekeyStore = { spk: { id: "spk-" + bytesToHex(rand(8)), priv: toB64(spkPriv) }, pqspk: { id: "pqspk-" + bytesToHex(rand(8)), dk: toB64(pqspk.secretKey) }, opks: {}, pqopks: {}, seenInitial: [] };
  const opkPublic: SignedPrekey[] = [];
  const pqopkPublic: SignedPrekey[] = [];
  for (let i = 0; i < count; i++) {
    const opkPriv = rand(32);
    const opkId = "opk-" + bytesToHex(rand(8));
    store.opks[opkId] = toB64(opkPriv);
    opkPublic.push(signPrekey(identity, "x25519-one-time", opkId, x25519.getPublicKey(opkPriv)));
    const pq = ml_kem768.keygen(rand(64));
    const pqId = "pqopk-" + bytesToHex(rand(8));
    store.pqopks[pqId] = toB64(pq.secretKey);
    pqopkPublic.push(signPrekey(identity, "mlkem768-one-time", pqId, pq.publicKey));
  }
  const protocols = opts.protocols ?? [...DEFAULT_PROTOCOLS];
  const capabilities = signCapabilities(identity, protocols);
  const base = {
    v: PQXDH_PROTOCOL,
    identity: publicIdentity(identity),
    capabilities,
    spk: signPrekey(identity, "x25519-signed", store.spk.id, x25519.getPublicKey(spkPriv)),
    pqspk: signPrekey(identity, "mlkem768-signed", store.pqspk.id, pqspk.publicKey),
  } as const;
  return {
    store,
    /** The server hands out each one-time key at most once; the index stands in for that here. */
    bundle(index?: number): PrekeyBundle {
      return { ...base, ...(index !== undefined && opkPublic[index] ? { opk: opkPublic[index], pqopk: pqopkPublic[index] } : {}) };
    },
  };
}

export function signCapabilities(identity: DeviceIdentitySecrets, protocols: string[] = [...DEFAULT_PROTOCOLS]): PrekeyBundle["capabilities"] {
  return { protocols, signature: signHybrid(`${PQXDH_PROTOCOL}/capabilities`, { protocols, userId: identity.userId, deviceId: identity.deviceId }, signingKeysOf(identity)) };
}

/** Assembles a bundle from published parts (as the server stores and hands them out). */
export function buildBundle(parts: { identity: PublicIdentity; capabilities: PrekeyBundle["capabilities"]; spk: SignedPrekey; pqspk: SignedPrekey; opk?: SignedPrekey; pqopk?: SignedPrekey }): PrekeyBundle {
  return { v: PQXDH_PROTOCOL, identity: parts.identity, capabilities: parts.capabilities, spk: parts.spk, pqspk: parts.pqspk, ...(parts.opk ? { opk: parts.opk } : {}), ...(parts.pqopk ? { pqopk: parts.pqopk } : {}) };
}

/**
 * Rotates the signed X25519 and ML-KEM last-resort prekeys (audit E-3). The
 * previous ones are retired, not deleted, and keep opening initial messages
 * for graceMs. Returns the NEW store (input untouched) and the public parts to
 * upload. Expired retired keys (and their replay records) are pruned.
 */
export function rotateSignedPrekeys(identity: DeviceIdentitySecrets, input: PrekeyStore, opts: { rand?: RandomSource; now?: Date; graceMs?: number } = {}) {
  const rand = opts.rand ?? randomBytes;
  const now = opts.now ?? new Date();
  const store: PrekeyStore = JSON.parse(JSON.stringify(input));
  const retired = store.retired ?? { spks: [], pqspks: [] };
  retired.spks.push({ id: store.spk.id, priv: store.spk.priv, retiredAt: now.toISOString() });
  retired.pqspks.push({ id: store.pqspk.id, dk: store.pqspk.dk, retiredAt: now.toISOString() });
  store.retired = retired;
  const spkPriv = rand(32);
  const pq = ml_kem768.keygen(rand(64));
  store.spk = { id: "spk-" + bytesToHex(rand(8)), priv: toB64(spkPriv), createdAt: now.toISOString() };
  store.pqspk = { id: "pqspk-" + bytesToHex(rand(8)), dk: toB64(pq.secretKey), createdAt: now.toISOString() };
  return {
    store: pruneRetiredPrekeys(store, now, opts.graceMs),
    spk: signPrekey(identity, "x25519-signed", store.spk.id, x25519.getPublicKey(spkPriv)),
    pqspk: signPrekey(identity, "mlkem768-signed", store.pqspk.id, pq.publicKey),
  };
}

/** Drops retired signed prekeys older than graceMs and the replay records bound to them. Pure. */
export function pruneRetiredPrekeys(input: PrekeyStore, now = new Date(), graceMs = SIGNED_PREKEY_GRACE_MS): PrekeyStore {
  const store: PrekeyStore = JSON.parse(JSON.stringify(input));
  if (!store.retired) return store;
  const alive = (at: string) => now.getTime() - Date.parse(at) < graceMs;
  store.retired.spks = store.retired.spks.filter((k) => alive(k.retiredAt));
  store.retired.pqspks = store.retired.pqspks.filter((k) => alive(k.retiredAt));
  const liveSpks = new Set([store.spk.id, ...store.retired.spks.map((k) => k.id)]);
  store.seenInitial = store.seenInitial.filter((entry) => liveSpks.has(entry.split("|")[0]));
  return store;
}

/** Adds one-time prekeys (replenishment). Returns the NEW store and the signed public keys to upload. */
export function addOneTimePrekeys(identity: DeviceIdentitySecrets, input: PrekeyStore, count: number, rand: RandomSource = randomBytes) {
  if (!Number.isSafeInteger(count) || count < 1) throw new PqxdhError("prekey_count");
  const store: PrekeyStore = JSON.parse(JSON.stringify(input));
  if (Object.keys(store.opks).length + count > MAX_ONE_TIME_PREKEYS) throw new PqxdhError("prekey_count", "Too many one-time prekeys.");
  const opks: SignedPrekey[] = [];
  const pqopks: SignedPrekey[] = [];
  for (let i = 0; i < count; i++) {
    const opkPriv = rand(32);
    const opkId = "opk-" + bytesToHex(rand(8));
    store.opks[opkId] = toB64(opkPriv);
    opks.push(signPrekey(identity, "x25519-one-time", opkId, x25519.getPublicKey(opkPriv)));
    const pq = ml_kem768.keygen(rand(64));
    const pqId = "pqopk-" + bytesToHex(rand(8));
    store.pqopks[pqId] = toB64(pq.secretKey);
    pqopks.push(signPrekey(identity, "mlkem768-one-time", pqId, pq.publicKey));
  }
  return { store, opks, pqopks };
}

/** Public signed prekeys of the CURRENT store (re-publish after a restart). */
export function publicSignedPrekeys(identity: DeviceIdentitySecrets, store: PrekeyStore) {
  return {
    spk: signPrekey(identity, "x25519-signed", store.spk.id, x25519.getPublicKey(fromB64(store.spk.priv))),
    pqspk: signPrekey(identity, "mlkem768-signed", store.pqspk.id, ml_kem768.getPublicKey(fromB64(store.pqspk.dk))),
  };
}

export function verifyCapabilities(bundle: PrekeyBundle): string[] | null {
  const c = bundle.capabilities;
  if (!c || !Array.isArray(c.protocols)) return null;
  const ok = verifyHybrid(`${PQXDH_PROTOCOL}/capabilities`, { protocols: c.protocols, userId: bundle.identity.userId, deviceId: bundle.identity.deviceId }, c.signature, bundle.identity).both;
  return ok ? [...c.protocols] : null;
}

// --- Key agreement ---------------------------------------------------------------
function sessionAd(initiator: PublicIdentity, responder: PublicIdentity) {
  const strip = (p: PublicIdentity) => ({ userId: p.userId, deviceId: p.deviceId, ik: p.ik, ed: p.ed25519_public_key, mldsa: p.ml_dsa_public_key });
  return canonicalBytes({ v: PQXDH_PROTOCOL, initiator: strip(initiator), responder: strip(responder) });
}

function deriveSk(dhs: Uint8Array[], ss: Uint8Array) {
  const ikm = concatBytes(new Uint8Array(32).fill(0xff), ...dhs, ss);
  const sk = hkdf(sha256, ikm, new Uint8Array(32), KDF_INFO, 64);
  return { skEc: sk.slice(0, 32), skPq: sk.slice(32) };
}

export type InitialMessage = {
  v: typeof PQXDH_PROTOCOL;
  initiator: PublicIdentity;
  responder: { userId: string; deviceId: string; ik: string };
  ek: string;
  spkId: string;
  opkId?: string;
  pqpkId: string;
  pqpkKind: "mlkem768-signed" | "mlkem768-one-time";
  pqct: string;
  first: RatchetMessage;
  signature: HybridSig;
};

/**
 * Initiator: verify the responder's bundle against the identity the caller
 * EXPECTS (pinned or verified), run the key agreement, and encrypt the first
 * message. Throws on any verification failure; never falls back silently.
 */
export function initiate(params: {
  self: DeviceIdentitySecrets;
  bundle: PrekeyBundle;
  expectedResponder: PublicIdentity;
  plaintext: string;
  rand?: RandomSource;
  pqEpochInterval?: number;
}): { state: RatchetState; message: InitialMessage } {
  const rand = params.rand ?? randomBytes;
  const b = params.bundle;
  if (!b || b.v !== PQXDH_PROTOCOL) throw new PqxdhError("bundle_version");
  const exp = params.expectedResponder;
  if (b.identity.ik !== exp.ik || b.identity.ed25519_public_key !== exp.ed25519_public_key || b.identity.ml_dsa_public_key !== exp.ml_dsa_public_key || b.identity.userId !== exp.userId || b.identity.deviceId !== exp.deviceId) {
    throw new PqxdhError("identity_mismatch", "The bundle's identity is not the expected one (possible key substitution).");
  }
  if (!verifyPublicIdentity(b.identity)) throw new PqxdhError("identity_binding");
  if (!verifyPrekey(b.identity, b.spk, "x25519-signed")) throw new PqxdhError("spk_signature");
  if (!verifyPrekey(b.identity, b.pqspk, "mlkem768-signed")) throw new PqxdhError("pqspk_signature");
  const protocols = verifyCapabilities(b);
  if (!protocols || !protocols.includes(PQXDH_PROTOCOL)) throw new PqxdhError("capabilities");
  const useOpk = b.opk && verifyPrekey(b.identity, b.opk, "x25519-one-time") ? b.opk : undefined;
  const pqpk = b.pqopk && verifyPrekey(b.identity, b.pqopk, "mlkem768-one-time") ? b.pqopk : b.pqspk;
  if (b.opk && !useOpk) throw new PqxdhError("opk_signature");
  if (b.pqopk && pqpk !== b.pqopk) throw new PqxdhError("pqopk_signature");

  const ikA = fromB64(params.self.ikPriv);
  const ekPriv = rand(32);
  const ekPub = x25519.getPublicKey(ekPriv);
  const spkB = fromB64(b.spk.pub);
  const dhs = [x25519.getSharedSecret(ikA, spkB), x25519.getSharedSecret(ekPriv, fromB64(b.identity.ik)), x25519.getSharedSecret(ekPriv, spkB)];
  if (useOpk) dhs.push(x25519.getSharedSecret(ekPriv, fromB64(useOpk.pub)));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(fromB64(pqpk.pub), rand(32));
  const { skEc, skPq } = deriveSk(dhs, sharedSecret);
  const me = publicIdentity(params.self);
  const ad = sessionAd(me, b.identity);
  let state = initInitiator({ skEc, skPq, responderRatchetPub: spkB, ad, rand, pqEpochInterval: params.pqEpochInterval });
  const first = encrypt(state, params.plaintext, rand);
  state = first.state;
  const unsigned = {
    v: PQXDH_PROTOCOL,
    initiator: me,
    responder: { userId: b.identity.userId, deviceId: b.identity.deviceId, ik: b.identity.ik },
    ek: toB64(ekPub),
    spkId: b.spk.id,
    ...(useOpk ? { opkId: useOpk.id } : {}),
    pqpkId: pqpk.id,
    pqpkKind: pqpk.kind as InitialMessage["pqpkKind"],
    pqct: toB64(cipherText),
    first: first.message,
  };
  return { state, message: { ...unsigned, signature: signHybrid(INIT_CONTEXT, unsigned, signingKeysOf(params.self)) } };
}

/**
 * Responder: authenticate the initiator against the identity the caller
 * expects for that account/device (pinned, verified, or first-seen per the
 * app's policy), consume one-time prekeys, derive the session and decrypt the
 * first message. Returns the NEW prekey store (one-time keys removed).
 */
export function respond(params: {
  self: DeviceIdentitySecrets;
  store: PrekeyStore;
  message: InitialMessage;
  expectedInitiator: PublicIdentity;
  rand?: RandomSource;
  pqEpochInterval?: number;
  /** When given, retired signed prekeys older than graceMs are pruned first (and refused). */
  now?: Date;
  graceMs?: number;
}): { state: RatchetState; store: PrekeyStore; plaintext: string } {
  const m = params.message;
  if (!m || m.v !== PQXDH_PROTOCOL) throw new PqxdhError("message_version");
  const me = publicIdentity(params.self);
  if (m.responder?.ik !== me.ik || m.responder.userId !== me.userId || m.responder.deviceId !== me.deviceId) throw new PqxdhError("wrong_recipient");
  const exp = params.expectedInitiator;
  if (m.initiator.ik !== exp.ik || m.initiator.ed25519_public_key !== exp.ed25519_public_key || m.initiator.ml_dsa_public_key !== exp.ml_dsa_public_key || m.initiator.userId !== exp.userId || m.initiator.deviceId !== exp.deviceId) {
    throw new PqxdhError("identity_mismatch", "The initiator is not the expected identity.");
  }
  if (!verifyPublicIdentity(m.initiator)) throw new PqxdhError("identity_binding");
  const { signature, ...unsigned } = m;
  if (!signature || !verifyHybrid(INIT_CONTEXT, unsigned, signature, m.initiator).both) throw new PqxdhError("initiator_signature");
  const store: PrekeyStore = params.now ? pruneRetiredPrekeys(params.store, params.now, params.graceMs) : JSON.parse(JSON.stringify(params.store));
  const spkEntry = m.spkId === store.spk.id ? store.spk : store.retired?.spks.find((k) => k.id === m.spkId);
  if (!spkEntry) throw new PqxdhError("unknown_spk", "Signed prekey unknown or expired.");
  const digest = `${m.spkId}|${bytesToHex(sha256(canonicalBytes(unsigned)))}`;
  const lastResortOnly = !m.opkId && m.pqpkKind === "mlkem768-signed";
  if (lastResortOnly && store.seenInitial.includes(digest)) throw new PqxdhError("replay", "Initial message replayed.");

  let opkPriv: Uint8Array | undefined;
  if (m.opkId) {
    const k = store.opks[m.opkId];
    if (!k) throw new PqxdhError("opk_used", "One-time prekey unknown or already used (replay).");
    opkPriv = fromB64(k);
    delete store.opks[m.opkId];
  }
  let dk: Uint8Array;
  if (m.pqpkKind === "mlkem768-one-time") {
    const k = store.pqopks[m.pqpkId];
    if (!k) throw new PqxdhError("pqopk_used");
    dk = fromB64(k);
    delete store.pqopks[m.pqpkId];
  } else {
    const pqEntry = m.pqpkId === store.pqspk.id ? store.pqspk : store.retired?.pqspks.find((k) => k.id === m.pqpkId);
    if (!pqEntry) throw new PqxdhError("unknown_pqspk");
    dk = fromB64(pqEntry.dk);
  }
  const ikB = fromB64(params.self.ikPriv);
  const spkPriv = fromB64(spkEntry.priv);
  const ekA = fromB64(m.ek);
  const dhs = [x25519.getSharedSecret(spkPriv, fromB64(m.initiator.ik)), x25519.getSharedSecret(ikB, ekA), x25519.getSharedSecret(spkPriv, ekA)];
  if (opkPriv) dhs.push(x25519.getSharedSecret(opkPriv, ekA));
  const ct = fromB64(m.pqct);
  if (ct.length !== 1088) throw new PqxdhError("pqct_length");
  const ss = ml_kem768.decapsulate(ct, dk);
  const { skEc, skPq } = deriveSk(dhs, ss);
  const ad = sessionAd(m.initiator, me);
  const state = initResponder({ skEc, skPq, ratchetKeyPair: { pub: x25519.getPublicKey(spkPriv), priv: spkPriv }, ad, pqEpochInterval: params.pqEpochInterval });
  const opened = decrypt(state, m.first, params.rand);
  if (lastResortOnly) {
    store.seenInitial.push(digest);
    while (store.seenInitial.length > MAX_SEEN_INITIAL) store.seenInitial.shift();
  }
  return { state: opened.state, store, plaintext: opened.plaintext };
}
