/*
 * EXPERIMENTAL - NOT REVIEWED - NOT USED BY ANY SENTIENT CLIENT.
 * Protocol id: "sentient-tr-v0-experimental".
 *
 * A Triple-Ratchet-style session: the Double Ratchet (Signal specification,
 * revision 4, 2025-11-04, sections 2-3; placed in the public domain) run in
 * parallel with a SPARSE post-quantum epoch ratchet over ML-KEM-768. Each
 * message key combines both, as in the specification's Triple Ratchet
 * (section 6, KDF_HYBRID in 7.2):
 *     mk = HKDF-SHA-256(salt = pq_mk, ikm = ec_mk, info = TR_INFO, 32)
 *
 * The post-quantum part is SPQR-INSPIRED, NOT SPQR: SPQR (section 5) runs the
 * ML-KEM Braid with erasure-coded chunks so that each message carries a small
 * fixed overhead. Here an epoch transition simply carries a whole ML-KEM-768
 * encapsulation key (1184 bytes) in one direction and a ciphertext (1088
 * bytes) back, attached to every message until acknowledged. That is simpler
 * to analyse but has bursty overhead, and it is NOT wire-compatible with SPQR.
 *
 * Properties intended (see docs/experimental/RATCHET.md for the threat model):
 *   - forward secrecy and post-compromise security against a CLASSICAL
 *     adversary at Double-Ratchet granularity (every DH ratchet step);
 *   - forward secrecy and post-compromise security against a QUANTUM
 *     adversary at EPOCH granularity (each completed ML-KEM exchange);
 *   - a message key stays secret if EITHER the classical or the PQ chain does.
 * None of this is proven or independently reviewed.
 *
 * Implementation rules:
 *   - all functions are pure: they take a state and return a NEW state; the
 *     input is never modified. Decryption commits nothing unless the AEAD
 *     verifies, so forged or malformed messages cannot change the session.
 *   - callers MUST persist the returned state before using the result
 *     (sending the message, showing the plaintext) and MUST serialize
 *     operations per session (see SessionMutex).
 *   - skipped-key storage is bounded per chain (MAX_SKIP) and in total
 *     (MAX_STORED_SKIPPED, oldest evicted).
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { canonicalBytes, fromB64, toB64, utf8Decode } from "../encoding/index.js";

export const RATCHET_PROTOCOL = "sentient-tr-v0-experimental" as const;
export const EXPERIMENTAL = true as const;

const DR_INFO = utf8ToBytes(`${RATCHET_PROTOCOL}:dr-root`);
const SCKA_INIT_INFO = utf8ToBytes(`${RATCHET_PROTOCOL}:Chain Start`);
const SCKA_RK_INFO = utf8ToBytes(`${RATCHET_PROTOCOL}:Chain Add Epoch`);
const SCKA_CHAINS_INFO = utf8ToBytes(`${RATCHET_PROTOCOL}:Epoch Chains`);
const TR_INFO = utf8ToBytes(`${RATCHET_PROTOCOL}:hybrid-message-key`);
const MSG_INFO = utf8ToBytes(`${RATCHET_PROTOCOL}:aead`);

export const MAX_SKIP = 1000;
export const MAX_STORED_SKIPPED = 2000;
export const MAX_PLAINTEXT_BYTES = 64 * 1024;
export const ML_KEM_EK_BYTES = 1184;
export const ML_KEM_CT_BYTES = 1088;
/**
 * Default rekey interval: a new post-quantum epoch is proposed at most once per
 * this many messages sent in the current epoch. Lower = faster post-quantum
 * healing after a compromise, more bandwidth (about 1.1 KB per transition
 * message). 1 = propose on every turn.
 */
export const DEFAULT_PQ_EPOCH_INTERVAL = 20;

export type Role = "initiator" | "responder";
export type RandomSource = (length: number) => Uint8Array;

type Chain = { ck: string; n: number };
type PqState = {
  epoch: number;
  root: string;
  send: Chain;
  /** Receiving chains for the current and the previous epoch only. */
  recv: Record<string, Chain>;
  /** Proposer side: our pending encapsulation key for `epoch`. */
  proposal: { epoch: number; ek: string; dk: string } | null;
  /** Responder side: ciphertext to repeat until the proposer acknowledges `epoch`. */
  answer: { epoch: number; ct: string } | null;
  /** Rekey interval (see DEFAULT_PQ_EPOCH_INTERVAL). */
  interval: number;
};

export type RatchetState = {
  v: 1;
  protocol: typeof RATCHET_PROTOCOL;
  role: Role;
  /** Session associated data (identity binding from the key agreement), base64. */
  ad: string;
  dhs: { pub: string; priv: string };
  dhr: string | null;
  rk: string;
  cks: string | null;
  ckr: string | null;
  ns: number;
  nr: number;
  pn: number;
  /** Skipped message keys, oldest first: [scope, key] where scope is "ec|<dh>|<n>" or "pq|<epoch>|<n>". */
  skipped: [string, string][];
  pq: PqState;
};

export type RatchetHeader = {
  v: typeof RATCHET_PROTOCOL;
  dh: string;
  pn: number;
  n: number;
  pqEpoch: number;
  pqN: number;
  /** Present while an epoch transition is in flight. */
  pqEk?: { epoch: number; ek: string };
  pqCt?: { epoch: number; ct: string };
};
export type RatchetMessage = { header: RatchetHeader; nonce: string; ciphertext: string };

export class RatchetError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = "RatchetError";
    this.code = code;
  }
}

// --- KDFs (specification section 2/5/7) ------------------------------------------
function kdfRk(rk: Uint8Array, dhOut: Uint8Array) {
  const out = hkdf(sha256, dhOut, rk, DR_INFO, 64);
  return { rk: out.slice(0, 32), ck: out.slice(32) };
}
function kdfCk(ck: Uint8Array) {
  return { mk: hmac(sha256, ck, new Uint8Array([0x01])), ck: hmac(sha256, ck, new Uint8Array([0x02])) };
}
function kdfSckaRk(root: Uint8Array, ss: Uint8Array) {
  return hkdf(sha256, ss, root, SCKA_RK_INFO, 32);
}
function epochChains(root: Uint8Array) {
  const out = hkdf(sha256, root, new Uint8Array(32), SCKA_CHAINS_INFO, 64);
  return { initiatorToResponder: out.slice(0, 32), responderToInitiator: out.slice(32) };
}
function kdfHybrid(ecMk: Uint8Array, pqMk: Uint8Array) {
  return hkdf(sha256, ecMk, pqMk, TR_INFO, 32);
}

const b = (s: string) => fromB64(s);

function clone(state: RatchetState): RatchetState {
  return JSON.parse(JSON.stringify(state));
}

function chainsFor(role: Role, root: Uint8Array) {
  const c = epochChains(root);
  return role === "initiator" ? { send: c.initiatorToResponder, recv: c.responderToInitiator } : { send: c.responderToInitiator, recv: c.initiatorToResponder };
}

/** Who proposes epoch e (e >= 1): the initiator proposes odd epochs, the responder even ones. */
export function proposerOf(epoch: number): Role {
  return epoch % 2 === 1 ? "initiator" : "responder";
}

// --- Initialisation (specification 3.3) ------------------------------------------
/**
 * Initiator ("Alice"). skEc / skPq: the two 32-byte halves of the key
 * agreement output. responderRatchetPub: the responder's signed prekey.
 */
export function initInitiator(params: { skEc: Uint8Array; skPq: Uint8Array; responderRatchetPub: Uint8Array; ad: Uint8Array; rand?: RandomSource; pqEpochInterval?: number }): RatchetState {
  const rand = params.rand ?? randomBytes;
  const priv = rand(32);
  const pub = x25519.getPublicKey(priv);
  const { rk, ck } = kdfRk(params.skEc, x25519.getSharedSecret(priv, params.responderRatchetPub));
  return {
    v: 1,
    protocol: RATCHET_PROTOCOL,
    role: "initiator",
    ad: toB64(params.ad),
    dhs: { pub: toB64(pub), priv: toB64(priv) },
    dhr: toB64(params.responderRatchetPub),
    rk: toB64(rk),
    cks: toB64(ck),
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: [],
    pq: initPq("initiator", params.skPq, params.pqEpochInterval),
  };
}

/** Responder ("Bob"): its signed prekey pair is the first ratchet key pair. */
export function initResponder(params: { skEc: Uint8Array; skPq: Uint8Array; ratchetKeyPair: { pub: Uint8Array; priv: Uint8Array }; ad: Uint8Array; pqEpochInterval?: number }): RatchetState {
  return {
    v: 1,
    protocol: RATCHET_PROTOCOL,
    role: "responder",
    ad: toB64(params.ad),
    dhs: { pub: toB64(params.ratchetKeyPair.pub), priv: toB64(params.ratchetKeyPair.priv) },
    dhr: null,
    rk: toB64(params.skEc),
    cks: null,
    ckr: null,
    ns: 0,
    nr: 0,
    pn: 0,
    skipped: [],
    pq: initPq("responder", params.skPq, params.pqEpochInterval),
  };
}

function initPq(role: Role, skPq: Uint8Array, interval = DEFAULT_PQ_EPOCH_INTERVAL): PqState {
  if (!Number.isSafeInteger(interval) || interval < 1 || interval > 10000) throw new RatchetError("pq_interval");
  const root = hkdf(sha256, skPq, new Uint8Array(32), SCKA_INIT_INFO, 32);
  const c = chainsFor(role, root);
  return { epoch: 0, root: toB64(root), send: { ck: toB64(c.send), n: 0 }, recv: { "0": { ck: toB64(c.recv), n: 0 } }, proposal: null, answer: null, interval };
}

// --- Skipped keys ------------------------------------------------------------------
function storeSkipped(state: RatchetState, scope: string, mk: Uint8Array) {
  state.skipped.push([scope, toB64(mk)]);
  while (state.skipped.length > MAX_STORED_SKIPPED) state.skipped.shift();
}
function takeSkipped(state: RatchetState, scope: string): Uint8Array | null {
  const i = state.skipped.findIndex(([s]) => s === scope);
  if (i < 0) return null;
  const [, mk] = state.skipped[i];
  state.skipped.splice(i, 1);
  return b(mk);
}

function skipEc(state: RatchetState, until: number) {
  if (state.ckr === null) return;
  if (until - state.nr > MAX_SKIP) throw new RatchetError("too_many_skipped", "Too many skipped messages in one chain.");
  let ck = b(state.ckr);
  while (state.nr < until) {
    const step = kdfCk(ck);
    storeSkipped(state, `ec|${state.dhr}|${state.nr}`, step.mk);
    ck = step.ck;
    state.nr += 1;
  }
  state.ckr = toB64(ck);
}

function pqRecvKey(state: RatchetState, epoch: number, n: number): Uint8Array {
  const cached = takeSkipped(state, `pq|${epoch}|${n}`);
  if (cached) return cached;
  const chain = state.pq.recv[String(epoch)];
  if (!chain) throw new RatchetError("pq_epoch_unknown", "Message for an unknown or expired post-quantum epoch.");
  if (n < chain.n) throw new RatchetError("pq_key_used", "Post-quantum message key already used (replay or duplicate).");
  if (n - chain.n > MAX_SKIP) throw new RatchetError("too_many_skipped");
  let ck = b(chain.ck);
  let i = chain.n;
  while (i < n) {
    const step = kdfCk(ck);
    storeSkipped(state, `pq|${epoch}|${i}`, step.mk);
    ck = step.ck;
    i += 1;
  }
  const step = kdfCk(ck);
  state.pq.recv[String(epoch)] = { ck: toB64(step.ck), n: n + 1 };
  return step.mk;
}

// --- Post-quantum epoch transitions ------------------------------------------------
function advanceEpoch(state: RatchetState, epoch: number, ss: Uint8Array) {
  if (epoch !== state.pq.epoch + 1) throw new RatchetError("pq_epoch_order");
  const root = kdfSckaRk(b(state.pq.root), ss);
  const c = chainsFor(state.role, root);
  const previous = state.pq.epoch;
  state.pq.epoch = epoch;
  state.pq.root = toB64(root);
  state.pq.send = { ck: toB64(c.send), n: 0 };
  state.pq.recv[String(epoch)] = { ck: toB64(c.recv), n: 0 };
  // Keep only the current and the previous epoch's receiving chains (forward secrecy).
  for (const key of Object.keys(state.pq.recv)) if (Number(key) < previous) delete state.pq.recv[key];
  state.skipped = state.skipped.filter(([scope]) => !scope.startsWith("pq|") || Number(scope.split("|")[1]) >= previous);
}

function processPqHeader(state: RatchetState, header: RatchetHeader, rand: RandomSource) {
  // Proposer: the peer answered our proposal.
  if (header.pqCt && state.pq.proposal && header.pqCt.epoch === state.pq.proposal.epoch) {
    const ct = b(header.pqCt.ct);
    if (ct.length !== ML_KEM_CT_BYTES) throw new RatchetError("pq_ct_length");
    const ss = ml_kem768.decapsulate(ct, b(state.pq.proposal.dk));
    advanceEpoch(state, state.pq.proposal.epoch, ss);
    state.pq.proposal = null; // dk deleted
  }
  // Responder: the peer proposes the next epoch and it is the peer's turn.
  if (header.pqEk && header.pqEk.epoch === state.pq.epoch + 1 && proposerOf(header.pqEk.epoch) !== state.role) {
    const ek = b(header.pqEk.ek);
    if (ek.length !== ML_KEM_EK_BYTES) throw new RatchetError("pq_ek_length");
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(ek, rand(32));
    advanceEpoch(state, header.pqEk.epoch, sharedSecret);
    state.pq.answer = { epoch: header.pqEk.epoch, ct: toB64(cipherText) };
  }
  // The proposer used the new epoch: our answer arrived.
  if (state.pq.answer && header.pqEpoch >= state.pq.answer.epoch) state.pq.answer = null;
}

// --- Message encryption ---------------------------------------------------------
function aeadKeys(mk: Uint8Array) {
  const out = hkdf(sha256, mk, new Uint8Array(32), MSG_INFO, 56);
  return { key: out.slice(0, 32), nonce: out.slice(32) };
}
function messageAd(state: RatchetState, header: RatchetHeader) {
  return concatBytes(b(state.ad), canonicalBytes(header));
}

export function encrypt(input: RatchetState, plaintext: string, rand: RandomSource = randomBytes): { state: RatchetState; message: RatchetMessage } {
  const state = clone(input);
  if (state.cks === null) throw new RatchetError("not_ready", "The responder cannot send before receiving the first message.");
  const bytes = utf8ToBytes(plaintext);
  if (bytes.length > MAX_PLAINTEXT_BYTES) throw new RatchetError("too_large");
  // Our turn to propose the next post-quantum epoch?
  const next = state.pq.epoch + 1;
  if (!state.pq.proposal && !state.pq.answer && proposerOf(next) === state.role && state.pq.send.n + 1 >= state.pq.interval) {
    const kp = ml_kem768.keygen(rand(64));
    state.pq.proposal = { epoch: next, ek: toB64(kp.publicKey), dk: toB64(kp.secretKey) };
  }
  const ec = kdfCk(b(state.cks));
  state.cks = toB64(ec.ck);
  const pqStep = kdfCk(b(state.pq.send.ck));
  const header: RatchetHeader = { v: RATCHET_PROTOCOL, dh: state.dhs.pub, pn: state.pn, n: state.ns, pqEpoch: state.pq.epoch, pqN: state.pq.send.n };
  if (state.pq.proposal) header.pqEk = { epoch: state.pq.proposal.epoch, ek: state.pq.proposal.ek };
  if (state.pq.answer) header.pqCt = { epoch: state.pq.answer.epoch, ct: state.pq.answer.ct };
  state.pq.send = { ck: toB64(pqStep.ck), n: state.pq.send.n + 1 };
  state.ns += 1;
  const { key, nonce } = aeadKeys(kdfHybrid(ec.mk, pqStep.mk));
  const ciphertext = xchacha20poly1305(key, nonce, messageAd(state, header)).encrypt(bytes);
  return { state, message: { header, nonce: toB64(nonce), ciphertext: toB64(ciphertext) } };
}

function validateHeader(h: unknown): asserts h is RatchetHeader {
  const x = h as RatchetHeader;
  const int = (v: unknown) => Number.isSafeInteger(v) && (v as number) >= 0;
  if (!x || typeof x !== "object" || x.v !== RATCHET_PROTOCOL) throw new RatchetError("version", "Unknown protocol version (downgrade or foreign message).");
  if (typeof x.dh !== "string" || !int(x.pn) || !int(x.n) || !int(x.pqEpoch) || !int(x.pqN)) throw new RatchetError("header_shape");
  if (fromB64(x.dh).length !== 32) throw new RatchetError("header_dh");
  if (x.pqEk && (!int(x.pqEk.epoch) || typeof x.pqEk.ek !== "string")) throw new RatchetError("header_pq");
  if (x.pqCt && (!int(x.pqCt.epoch) || typeof x.pqCt.ct !== "string")) throw new RatchetError("header_pq");
}

export function decrypt(input: RatchetState, message: RatchetMessage, rand: RandomSource = randomBytes): { state: RatchetState; plaintext: string } {
  const header = message?.header;
  validateHeader(header);
  if (typeof message.nonce !== "string" || typeof message.ciphertext !== "string") throw new RatchetError("message_shape");
  const state = clone(input);

  // Post-quantum epoch bookkeeping first (a ciphertext answering our proposal
  // is needed to derive the key of this very message). Nothing is committed
  // unless the AEAD below verifies: `state` is a private copy until returned.
  if (header.pqEpoch + 1 < state.pq.epoch) throw new RatchetError("pq_epoch_expired", "Message from an expired post-quantum epoch.");
  processPqHeader(state, header, rand);
  if (header.pqEpoch > state.pq.epoch) throw new RatchetError("pq_epoch_ahead", "Message from a post-quantum epoch this session never agreed.");

  // Classical message key (specification 3.5).
  let ecMk = takeSkipped(state, `ec|${header.dh}|${header.n}`);
  if (!ecMk) {
    if (header.dh !== state.dhr) {
      skipEc(state, header.pn);
      // DH ratchet step.
      state.pn = state.ns;
      state.ns = 0;
      state.nr = 0;
      state.dhr = header.dh;
      const r1 = kdfRk(b(state.rk), x25519.getSharedSecret(b(state.dhs.priv), b(state.dhr)));
      state.ckr = toB64(r1.ck);
      const priv = rand(32);
      state.dhs = { pub: toB64(x25519.getPublicKey(priv)), priv: toB64(priv) };
      const r2 = kdfRk(r1.rk, x25519.getSharedSecret(priv, b(state.dhr)));
      state.rk = toB64(r2.rk);
      state.cks = toB64(r2.ck);
    }
    if (header.n < state.nr) throw new RatchetError("ec_key_used", "Message key already used (replay or duplicate).");
    skipEc(state, header.n);
    const step = kdfCk(b(state.ckr!));
    state.ckr = toB64(step.ck);
    state.nr += 1;
    ecMk = step.mk;
  }
  const pqMk = pqRecvKey(state, header.pqEpoch, header.pqN);
  const { key, nonce } = aeadKeys(kdfHybrid(ecMk, pqMk));
  if (message.nonce !== toB64(nonce)) throw new RatchetError("nonce_mismatch");
  let bytes: Uint8Array;
  try {
    bytes = xchacha20poly1305(key, nonce, messageAd(state, header)).decrypt(b(message.ciphertext));
  } catch {
    throw new RatchetError("authentication", "Message failed authentication.");
  }
  return { state, plaintext: utf8Decode(bytes, { fatal: true }) };
}

/** Serialize operations per session: run(fn) executes fns one at a time, in call order. */
export class SessionMutex {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(fn: () => Promise<T> | T): Promise<T> {
    const result = this.tail.then(fn, fn);
    this.tail = result.catch(() => undefined);
    return result;
  }
}

/** Size of the post-quantum material a message carries (bytes), for overhead measurement. */
export function pqOverheadBytes(message: RatchetMessage): number {
  return (message.header.pqEk ? fromB64(message.header.pqEk.ek).length : 0) + (message.header.pqCt ? fromB64(message.header.pqCt.ct).length : 0);
}
