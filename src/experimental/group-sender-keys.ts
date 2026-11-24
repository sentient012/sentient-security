/*
 * EXPERIMENTAL - NOT REVIEWED - NOT USED BY ANY SENTIENT CLIENT.
 * Protocol id: "sentient-group-sk-v0-experimental".
 *
 * Sender-key group messaging with per-sender symmetric ratchets, as a possible
 * successor to sentient-group-*-v1's per-epoch group key.
 *
 * Deployed v1: one group key per epoch, used for every message in it. Anyone
 * who obtains it reads the whole epoch, past and future.
 * Here: each member device has its own sender chain per epoch:
 *     mk_i, ck_{i+1} = HMAC(ck_i, 0x01), HMAC(ck_i, 0x02)
 * Chain keys and message keys are deleted as soon as they are used, so a device
 * compromise reveals only messages after the compromise in the current epoch
 * (forward secrecy inside an epoch). Membership changes start a new epoch with
 * new sender chains for every remaining member (removed members lose access,
 * post-compromise recovery at epoch granularity). Every message is signed
 * with the sender's hybrid identity key (Ed25519 + ML-DSA-65), so a member
 * cannot forge another member's messages, which a shared symmetric key alone
 * would allow.
 *
 * A sender's initial chain key ("sender key distribution") must reach the
 * other members over AUTHENTICATED pairwise channels (the experimental
 * sentient-tr-v0 sessions). This module only defines the chain, the message
 * format and the distribution payload.
 *
 * NOT provided: the strong group properties of MLS (RFC 9420), such as
 * efficient post-compromise security for large groups or agreed group state.
 * See docs/experimental/GROUPS.md.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { canonicalBytes, fromB64, toB64, utf8Decode } from "../encoding/index.js";
import { signHybrid, verifyHybrid } from "../business/core.js";
import { signingKeysOf, type DeviceIdentitySecrets, type PublicIdentity } from "./pqxdh.js";

export const GROUP_SK_PROTOCOL = "sentient-group-sk-v0-experimental" as const;
const SIGN_CONTEXT = `${GROUP_SK_PROTOCOL}/message`;
const AEAD_INFO = utf8ToBytes(`${GROUP_SK_PROTOCOL}:aead`);
export const MAX_GROUP_SKIP = 2000;

export class GroupSenderKeyError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = "GroupSenderKeyError";
    this.code = code;
  }
}

/** What a sender gives each member (over a pairwise session) for one epoch. */
export type SenderKeyDistribution = { v: typeof GROUP_SK_PROTOCOL; groupId: string; epoch: number; senderDeviceId: string; senderUserId: string; chainKey: string; iteration: number };

/** One member's local view of one sender chain. */
export type SenderChainState = { groupId: string; epoch: number; senderDeviceId: string; senderUserId: string; ck: string; iteration: number; skipped: [number, string][] };

export type GroupMessage = {
  v: typeof GROUP_SK_PROTOCOL;
  groupId: string;
  epoch: number;
  senderUserId: string;
  senderDeviceId: string;
  iteration: number;
  nonce: string;
  ciphertext: string;
  signature: { ed25519: string; mlDsa: string };
};

export function newSenderChain(params: { groupId: string; epoch: number; sender: DeviceIdentitySecrets; rand?: (n: number) => Uint8Array }): { own: SenderChainState; distribution: SenderKeyDistribution } {
  const ck = toB64((params.rand ?? randomBytes)(32));
  const own: SenderChainState = { groupId: params.groupId, epoch: params.epoch, senderDeviceId: params.sender.deviceId, senderUserId: params.sender.userId, ck, iteration: 0, skipped: [] };
  return { own, distribution: { v: GROUP_SK_PROTOCOL, groupId: params.groupId, epoch: params.epoch, senderDeviceId: params.sender.deviceId, senderUserId: params.sender.userId, chainKey: ck, iteration: 0 } };
}

export function acceptDistribution(d: SenderKeyDistribution): SenderChainState {
  if (!d || d.v !== GROUP_SK_PROTOCOL || fromB64(d.chainKey).length !== 32 || !Number.isSafeInteger(d.iteration) || d.iteration < 0) throw new GroupSenderKeyError("distribution");
  return { groupId: d.groupId, epoch: d.epoch, senderDeviceId: d.senderDeviceId, senderUserId: d.senderUserId, ck: d.chainKey, iteration: d.iteration, skipped: [] };
}

function step(ck: Uint8Array) {
  return { mk: hmac(sha256, ck, new Uint8Array([1])), ck: hmac(sha256, ck, new Uint8Array([2])) };
}
function aead(mk: Uint8Array) {
  const out = hkdf(sha256, mk, new Uint8Array(32), AEAD_INFO, 56);
  return { key: out.slice(0, 32), nonce: out.slice(32) };
}
function header(m: Omit<GroupMessage, "nonce" | "ciphertext" | "signature">) {
  return { v: m.v, groupId: m.groupId, epoch: m.epoch, senderUserId: m.senderUserId, senderDeviceId: m.senderDeviceId, iteration: m.iteration };
}

export function encryptGroup(own: SenderChainState, sender: DeviceIdentitySecrets, plaintext: string): { state: SenderChainState; message: GroupMessage } {
  if (own.senderDeviceId !== sender.deviceId) throw new GroupSenderKeyError("not_own_chain");
  const s = step(fromB64(own.ck));
  const h = header({ v: GROUP_SK_PROTOCOL, groupId: own.groupId, epoch: own.epoch, senderUserId: own.senderUserId, senderDeviceId: own.senderDeviceId, iteration: own.iteration });
  const { key, nonce } = aead(s.mk);
  const ciphertext = xchacha20poly1305(key, nonce, canonicalBytes(h)).encrypt(utf8ToBytes(plaintext));
  const unsigned = { ...h, nonce: toB64(nonce), ciphertext: toB64(ciphertext) };
  return {
    state: { ...own, ck: toB64(s.ck), iteration: own.iteration + 1 },
    message: { ...unsigned, signature: signHybrid(SIGN_CONTEXT, unsigned, signingKeysOf(sender)) },
  };
}

/**
 * Verify the sender's signature against its PINNED identity first, then
 * decrypt. Returns the new chain state (used keys deleted).
 */
export function decryptGroup(chain: SenderChainState, message: GroupMessage, senderIdentity: PublicIdentity): { state: SenderChainState; plaintext: string } {
  if (!message || message.v !== GROUP_SK_PROTOCOL) throw new GroupSenderKeyError("version");
  if (message.groupId !== chain.groupId || message.epoch !== chain.epoch || message.senderDeviceId !== chain.senderDeviceId || message.senderUserId !== chain.senderUserId) throw new GroupSenderKeyError("wrong_chain", "Message does not belong to this sender chain (group, epoch or sender).");
  if (senderIdentity.deviceId !== message.senderDeviceId || senderIdentity.userId !== message.senderUserId) throw new GroupSenderKeyError("wrong_sender");
  const { signature, ...unsigned } = message;
  if (!signature || !verifyHybrid(SIGN_CONTEXT, unsigned, signature, senderIdentity).both) throw new GroupSenderKeyError("signature", "The sender's signature is not valid.");
  if (!Number.isSafeInteger(message.iteration) || message.iteration < 0) throw new GroupSenderKeyError("iteration");
  const state: SenderChainState = JSON.parse(JSON.stringify(chain));
  let mk: Uint8Array | null = null;
  if (message.iteration < state.iteration) {
    const i = state.skipped.findIndex(([n]) => n === message.iteration);
    if (i < 0) throw new GroupSenderKeyError("key_used", "Message key already used or deleted (replay).");
    mk = fromB64(state.skipped[i][1]);
    state.skipped.splice(i, 1);
  } else {
    if (message.iteration - state.iteration > MAX_GROUP_SKIP) throw new GroupSenderKeyError("too_many_skipped");
    let ck = fromB64(state.ck);
    while (state.iteration < message.iteration) {
      const s = step(ck);
      state.skipped.push([state.iteration, toB64(s.mk)]);
      if (state.skipped.length > MAX_GROUP_SKIP) state.skipped.shift();
      ck = s.ck;
      state.iteration += 1;
    }
    const s = step(ck);
    mk = s.mk;
    state.ck = toB64(s.ck);
    state.iteration += 1;
  }
  const { key, nonce } = aead(mk);
  if (toB64(nonce) !== message.nonce) throw new GroupSenderKeyError("nonce");
  let bytes: Uint8Array;
  try {
    bytes = xchacha20poly1305(key, nonce, canonicalBytes(header(message))).decrypt(fromB64(message.ciphertext));
  } catch {
    throw new GroupSenderKeyError("authentication");
  }
  return { state, plaintext: utf8Decode(bytes, { fatal: true }) };
}
