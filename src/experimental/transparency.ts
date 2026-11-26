/*
 * NOT REVIEWED. Published as @sentient012/security/session/transparency since 0.4.0.
 * Protocol id: "sentient-kt-v0-experimental".
 *
 * Key transparency log for Sentient's public-key directory.
 *
 * Every public key a client relies on (a device's session identity, an
 * account's signed device list, a business's signed roster, a call key
 * binding) is appended to a log as one entry (an exact UTF-8 string chosen by
 * the server). The log is a Merkle tree with the RFC 9162 (Certificate
 * Transparency 2.0) hashing rules:
 *   leaf  = SHA-256(0x00 || entry bytes)
 *   node  = SHA-256(0x01 || left || right)
 * The log operator signs tree heads (size, root, time) with a hybrid
 * Ed25519 + ML-DSA-65 key whose public half clients pin.
 *
 * What clients get:
 *   - inclusion: the exact key a client is about to trust is in the log at a
 *     signed tree head (a key shown to one client only must be logged, where
 *     its owner's own devices can see it: owner monitoring);
 *   - append-only: a client checks every new tree head it sees against the
 *     last one with a consistency proof, so the log cannot drop or rewrite an
 *     entry it has already shown this client;
 *   - freshness: a tree head older than the client's limit is refused.
 *
 * NOT provided: detection of a split view (different, individually
 * consistent logs for different clients) unless clients compare tree heads
 * with each other (gossip) or an independent auditor does; privacy of the
 * directory (entries are readable, as the directory already is); and any
 * guarantee before a client has first pinned a tree head.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { signHybrid, verifyHybrid } from "../business/core.js";

export const KT_PROTOCOL = "sentient-kt-v0-experimental" as const;
const TREE_HEAD_CONTEXT = `${KT_PROTOCOL}:tree-head`;
export const EMPTY_ROOT = bytesToHex(sha256(new Uint8Array(0)));

export class TransparencyError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = "TransparencyError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Hashing (RFC 9162 section 2.1.1)
// ---------------------------------------------------------------------------
export function leafHash(entry: string | Uint8Array): Uint8Array {
  const bytes = typeof entry === "string" ? utf8ToBytes(entry) : entry;
  const input = new Uint8Array(bytes.length + 1);
  input[0] = 0x00;
  input.set(bytes, 1);
  return sha256(input);
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const input = new Uint8Array(65);
  input[0] = 0x01;
  input.set(left, 1);
  input.set(right, 33);
  return sha256(input);
}

/** Largest power of two strictly smaller than n (n >= 2). */
function split(n: number) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

const isOdd = (x: number) => x % 2 === 1;
const half = (x: number) => Math.floor(x / 2);
const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
const toHash = (value: Uint8Array | string) => (typeof value === "string" ? hexToBytes(value) : value);

/**
 * A Merkle tree over leaf hashes (the log operator's side; clients only
 * verify). Subtree roots are memoized, so a root or proof costs O(n) once and
 * little after.
 */
export class MerkleTree {
  private readonly leaves: Uint8Array[];
  private readonly memo = new Map<string, Uint8Array>();
  constructor(leafHashes: Uint8Array[]) {
    this.leaves = leafHashes;
  }
  get size() {
    return this.leaves.length;
  }
  private mth(start: number, end: number): Uint8Array {
    const n = end - start;
    if (n === 0) return sha256(new Uint8Array(0));
    if (n === 1) return this.leaves[start];
    const key = `${start}:${end}`;
    const hit = this.memo.get(key);
    if (hit) return hit;
    const k = split(n);
    const value = nodeHash(this.mth(start, start + k), this.mth(start + k, end));
    this.memo.set(key, value);
    return value;
  }
  /** Root of the first `size` leaves. */
  root(size = this.size): Uint8Array {
    if (size < 0 || size > this.size) throw new TransparencyError("size");
    return this.mth(0, size);
  }
  /** RFC 6962 PATH(m, D[0:size]). */
  inclusionProof(index: number, size = this.size): Uint8Array[] {
    if (index < 0 || index >= size || size > this.size) throw new TransparencyError("index");
    const path = (m: number, start: number, end: number): Uint8Array[] => {
      const n = end - start;
      if (n <= 1) return [];
      const k = split(n);
      return m < k ? [...path(m, start, start + k), this.mth(start + k, end)] : [...path(m - k, start + k, end), this.mth(start, start + k)];
    };
    return path(index, 0, size);
  }
  /** RFC 6962 PROOF(m, D[0:n]). */
  consistencyProof(first: number, second = this.size): Uint8Array[] {
    if (first < 1 || first > second || second > this.size) throw new TransparencyError("size");
    const sub = (m: number, start: number, end: number, whole: boolean): Uint8Array[] => {
      const n = end - start;
      if (m === n) return whole ? [] : [this.mth(start, end)];
      const k = split(n);
      return m <= k
        ? [...sub(m, start, start + k, whole), this.mth(start + k, end)]
        : [...sub(m - k, start + k, end, false), this.mth(start, start + k)];
    };
    return sub(first, 0, second, true);
  }
}

// ---------------------------------------------------------------------------
// Verification (RFC 9162 sections 2.1.3.2 and 2.1.4.2)
// ---------------------------------------------------------------------------
export function verifyInclusion(params: { index: number; size: number; leaf: Uint8Array; path: (Uint8Array | string)[]; root: Uint8Array | string }): boolean {
  const { index, size } = params;
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = params.leaf;
  for (const raw of params.path) {
    const p = toHash(raw);
    if (p.length !== 32 || sn === 0) return false;
    if (isOdd(fn) || fn === sn) {
      r = nodeHash(p, r);
      if (!isOdd(fn)) while (!isOdd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else {
      r = nodeHash(r, p);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equal(r, toHash(params.root));
}

export function verifyConsistency(params: { first: number; second: number; firstRoot: Uint8Array | string; secondRoot: Uint8Array | string; proof: (Uint8Array | string)[] }): boolean {
  const { first, second } = params;
  const firstRoot = toHash(params.firstRoot);
  const secondRoot = toHash(params.secondRoot);
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 1 || first > second) return false;
  const proof = params.proof.map(toHash);
  if (proof.some((p) => p.length !== 32)) return false;
  if (first === second) return proof.length === 0 && equal(firstRoot, secondRoot);
  // RFC 9162: when the first tree is a complete subtree, its root starts the path.
  const path = isPowerOfTwo(first) ? [firstRoot, ...proof] : proof;
  if (!path.length) return false;
  let fn = first - 1;
  let sn = second - 1;
  while (isOdd(fn)) { fn = half(fn); sn = half(sn); }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (isOdd(fn) || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if (!isOdd(fn)) while (!isOdd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else {
      sr = nodeHash(sr, c);
    }
    fn = half(fn);
    sn = half(sn);
  }
  return sn === 0 && equal(fr, firstRoot) && equal(sr, secondRoot);
}

function isPowerOfTwo(x: number) {
  let v = x;
  while (v > 1) {
    if (isOdd(v)) return false;
    v = half(v);
  }
  return v === 1;
}

// ---------------------------------------------------------------------------
// Signed tree heads
// ---------------------------------------------------------------------------
export type TreeHead = { v: typeof KT_PROTOCOL; logId: string; size: number; root: string; timestamp: string };
export type SignedTreeHead = TreeHead & { signature: { ed25519: string; mlDsa: string } };
export type LogPublicKey = { logId: string; ed25519_public_key: string; ml_dsa_public_key: string };

type SigningKeys = { ed25519PrivateKey: Uint8Array; ed25519PublicKey: Uint8Array; mlDsaSecretKey: Uint8Array; mlDsaPublicKey: Uint8Array };

export function signTreeHead(head: Omit<TreeHead, "v">, signingKeys: SigningKeys): SignedTreeHead {
  const unsigned: TreeHead = { v: KT_PROTOCOL, logId: head.logId, size: head.size, root: head.root, timestamp: head.timestamp };
  return { ...unsigned, signature: signHybrid(TREE_HEAD_CONTEXT, unsigned, signingKeys) };
}

function wellFormed(sth: any): sth is SignedTreeHead {
  return !!sth && sth.v === KT_PROTOCOL && typeof sth.logId === "string" && Number.isSafeInteger(sth.size) && sth.size >= 0
    && typeof sth.root === "string" && /^[0-9a-f]{64}$/.test(sth.root) && typeof sth.timestamp === "string" && Number.isFinite(Date.parse(sth.timestamp))
    && !!sth.signature && typeof sth.signature.ed25519 === "string" && typeof sth.signature.mlDsa === "string";
}

/** Both signatures must verify under the pinned log key. */
export function verifyTreeHead(sth: unknown, logKey: LogPublicKey): sth is SignedTreeHead {
  if (!wellFormed(sth) || sth.logId !== logKey.logId) return false;
  const { signature, ...unsigned } = sth;
  return verifyHybrid(TREE_HEAD_CONTEXT, { v: unsigned.v, logId: unsigned.logId, size: unsigned.size, root: unsigned.root, timestamp: unsigned.timestamp }, signature, logKey).both;
}

export type TreeHeadVerdict =
  | { status: "first_seen" | "unchanged" | "advanced"; head: SignedTreeHead }
  | { status: "rejected"; reason: "signature" | "rollback" | "equivocation" | "inconsistent" | "stale" | "future" };

export const TREE_HEAD_MAX_AGE_MS = 24 * 60 * 60 * 1000;
const CLOCK_SKEW_MS = 10 * 60 * 1000;

/**
 * A newly fetched tree head against the last one this client accepted.
 * `consistency` is the proof from pinned.size to next.size (ignored when the
 * sizes are equal).
 */
export function evaluateTreeHead(pinned: SignedTreeHead | null, next: unknown, consistency: (Uint8Array | string)[], logKey: LogPublicKey, opts: { now?: Date; maxAgeMs?: number } = {}): TreeHeadVerdict {
  if (!verifyTreeHead(next, logKey)) return { status: "rejected", reason: "signature" };
  const now = (opts.now ?? new Date()).getTime();
  const at = Date.parse(next.timestamp);
  if (at > now + CLOCK_SKEW_MS) return { status: "rejected", reason: "future" };
  if (now - at > (opts.maxAgeMs ?? TREE_HEAD_MAX_AGE_MS)) return { status: "rejected", reason: "stale" };
  if (!pinned) return { status: "first_seen", head: next };
  if (next.size < pinned.size) return { status: "rejected", reason: "rollback" };
  if (Date.parse(next.timestamp) < Date.parse(pinned.timestamp)) return { status: "rejected", reason: "rollback" };
  if (next.size === pinned.size) return next.root === pinned.root ? { status: "unchanged", head: next } : { status: "rejected", reason: "equivocation" };
  if (pinned.size === 0) return { status: "advanced", head: next };
  return verifyConsistency({ first: pinned.size, second: next.size, firstRoot: pinned.root, secondRoot: next.root, proof: consistency })
    ? { status: "advanced", head: next }
    : { status: "rejected", reason: "inconsistent" };
}

/** The exact entry string is in the log at this signed tree head. */
export function verifyEntryInclusion(params: { entry: string; index: number; head: SignedTreeHead; path: (Uint8Array | string)[] }): boolean {
  return verifyInclusion({ index: params.index, size: params.head.size, leaf: leafHash(params.entry), path: params.path, root: params.head.root });
}

export const hashToHex = (h: Uint8Array) => bytesToHex(h);
