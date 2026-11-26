/*
 * NOT REVIEWED. Off unless the app enables it.
 * Protocol id: "sentient-device-list-v0-experimental".
 *
 * Authenticated multi-device membership for one Sentient account.
 *
 * Today every client trusts the device keys the server lists for an account,
 * so the server can silently add a device and read new messages. Here the
 * device list is a signed, versioned statement:
 *   - version n+1 must be signed (hybrid Ed25519 + ML-DSA-65) by a device that
 *     was listed in version n: an existing device approves every change;
 *   - versions only increase (no rollback to an older list);
 *   - every list carries a signed expiry and is re-signed periodically, so a
 *     server that keeps serving an old list is detected (freeze, audit E-4);
 *   - peers exchange (version, digest) of the lists they pinned inside
 *     authenticated sessions, so a server that shows different lists to
 *     different people is detected (fork / equivocation, audit E-4);
 *   - peers pin the last accepted list per account and classify every new one
 *     as unchanged / devices added / devices removed / identity reset;
 *   - an "identity reset" (no listed device can sign, e.g. every device was
 *     lost and the account was recovered) is never accepted silently: the app
 *     must show it and should require re-verification.
 *
 * This is NOT key transparency: a server that equivocates towards two people
 * who never talk to each other is not detected. A public append-only log with
 * client auditing would close that gap (see THREAT_MODEL.md).
 *
 * Sentient specifics: account recovery (recovery phrase + PIN, or passkey)
 * makes a NEW device without any old one. That is exactly the identity-reset
 * case, and it is surfaced, not hidden. Business Terminal devices are not
 * consumer devices; a business's devices belong in a separate,
 * organization-scoped list and must never appear in a consumer's list.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { canonicalBytes } from "../encoding/index.js";
import { signHybrid, verifyHybrid } from "../business/core.js";
import type { PublicIdentity } from "./pqxdh.js";
import { signingKeysOf, verifyPublicIdentity, type DeviceIdentitySecrets } from "./pqxdh.js";

export const DEVICE_LIST_PROTOCOL = "sentient-device-list-v0-experimental" as const;
const CONTEXT = `${DEVICE_LIST_PROTOCOL}/statement`;
export const MAX_DEVICES = 32;
/** Every list expires this long after it was issued. */
export const DEVICE_LIST_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
/** Devices re-sign their account's list this often (refreshDeviceList / needsRefresh). */
export const DEVICE_LIST_REFRESH_MS = 7 * 24 * 60 * 60 * 1000;

export type DeviceListStatement = {
  v: typeof DEVICE_LIST_PROTOCOL;
  userId: string;
  version: number;
  devices: PublicIdentity[];
  issuedAt: string;
  /** Signed expiry. A list without one is treated as expired. */
  expiresAt?: string;
  signerDeviceId: string;
  signature: { ed25519: string; mlDsa: string };
};

export class DeviceListError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = "DeviceListError";
    this.code = code;
  }
}

function body(s: Omit<DeviceListStatement, "signature">) {
  return { v: s.v, userId: s.userId, version: s.version, devices: s.devices, issuedAt: s.issuedAt, ...(s.expiresAt !== undefined ? { expiresAt: s.expiresAt } : {}), signerDeviceId: s.signerDeviceId };
}

/** Commitment to one exact signed list. Peers exchange (version, digest) inside authenticated sessions to detect forks. */
export function deviceListDigest(s: DeviceListStatement): string {
  return bytesToHex(sha256(canonicalBytes({ ...body(s), signature: s.signature })));
}

/** Signs a new list. The signer must be in `devices` (it approves the result). */
export function signDeviceList(params: { signer: DeviceIdentitySecrets; userId: string; version: number; devices: PublicIdentity[]; issuedAt?: string; expiresAt?: string }): DeviceListStatement {
  if (!Number.isSafeInteger(params.version) || params.version < 1) throw new DeviceListError("version");
  if (params.devices.length === 0 || params.devices.length > MAX_DEVICES) throw new DeviceListError("device_count");
  const ids = new Set(params.devices.map((d) => d.deviceId));
  if (ids.size !== params.devices.length) throw new DeviceListError("duplicate_device");
  if (!ids.has(params.signer.deviceId)) throw new DeviceListError("signer_not_listed");
  const issuedAt = params.issuedAt ?? new Date().toISOString();
  const expiresAt = params.expiresAt ?? new Date(Date.parse(issuedAt) + DEVICE_LIST_LIFETIME_MS).toISOString();
  if (!(Date.parse(expiresAt) > Date.parse(issuedAt))) throw new DeviceListError("expiry");
  const unsigned = { v: DEVICE_LIST_PROTOCOL, userId: params.userId, version: params.version, devices: params.devices, issuedAt, expiresAt, signerDeviceId: params.signer.deviceId } as const;
  return { ...unsigned, signature: signHybrid(CONTEXT, body(unsigned), signingKeysOf(params.signer)) };
}

/** Structural and self-signature checks; does not decide trust (see evaluateDeviceList). */
function verifyStatement(s: DeviceListStatement, signerKeys: PublicIdentity): boolean {
  if (!s || s.v !== DEVICE_LIST_PROTOCOL || !Array.isArray(s.devices)) return false;
  for (const d of s.devices) if (d.userId !== s.userId || !verifyPublicIdentity(d)) return false;
  return verifyHybrid(CONTEXT, body(s), s.signature, signerKeys).both;
}

export type DeviceListVerdict =
  | { status: "first_seen"; accepted: DeviceListStatement }
  | { status: "unchanged"; accepted: DeviceListStatement }
  | { status: "changed"; accepted: DeviceListStatement; added: string[]; removed: string[]; approvedBy: string }
  | { status: "identity_reset"; candidate: DeviceListStatement; reason: string }
  | { status: "stale"; pinned: DeviceListStatement; reason: "expired" }
  | { status: "rejected"; reason: string };

/**
 * Compare a newly fetched list with the pinned one.
 *   first_seen     - nothing pinned: accepted on trust-on-first-use (the app should
 *                    offer verification, see identity-verification.ts)
 *   unchanged      - same version and contents, not expired
 *   stale          - same version and contents, but EXPIRED: newer lists are being
 *                    withheld (or every device of that account has been offline
 *                    for weeks). The app warns and must not add new sessions.
 *   changed        - newer version signed by a device in the pinned list
 *   identity_reset - newer version NOT signed by any pinned device: do not
 *                    accept silently; require the user to re-verify
 *   rejected       - invalid, expired on arrival, rolled back, or the same
 *                    version with other contents (equivocation)
 */
export function evaluateDeviceList(pinned: DeviceListStatement | null, candidate: DeviceListStatement, opts: { now?: Date } = {}): DeviceListVerdict {
  if (!candidate || candidate.v !== DEVICE_LIST_PROTOCOL) return { status: "rejected", reason: "version" };
  const now = (opts.now ?? new Date()).getTime();
  const expired = (s: DeviceListStatement) => !s.expiresAt || !(Date.parse(s.expiresAt) > now);
  const signer = candidate.devices.find((d) => d.deviceId === candidate.signerDeviceId);
  if (!signer) return { status: "rejected", reason: "signer_not_listed" };
  if (!pinned) {
    if (!verifyStatement(candidate, signer)) return { status: "rejected", reason: "signature" };
    return expired(candidate) ? { status: "rejected", reason: "expired" } : { status: "first_seen", accepted: candidate };
  }
  if (candidate.userId !== pinned.userId) return { status: "rejected", reason: "wrong_account" };
  if (candidate.version < pinned.version) return { status: "rejected", reason: "rollback" };
  if (candidate.version === pinned.version) {
    if (!(JSON.stringify(body(candidate)) === JSON.stringify(body(pinned)) && candidate.signature.ed25519 === pinned.signature.ed25519)) return { status: "rejected", reason: "equivocation" };
    return expired(pinned) ? { status: "stale", pinned, reason: "expired" } : { status: "unchanged", accepted: pinned };
  }
  // The change must be approved by a device the peer already trusts.
  const approver = pinned.devices.find((d) => d.deviceId === candidate.signerDeviceId);
  const keysMatch = approver && approver.ed25519_public_key === signer.ed25519_public_key && approver.ml_dsa_public_key === signer.ml_dsa_public_key;
  if (!keysMatch) {
    return verifyStatement(candidate, signer)
      ? { status: "identity_reset", candidate, reason: "not_signed_by_a_trusted_device" }
      : { status: "rejected", reason: "signature" };
  }
  if (!verifyStatement(candidate, approver!)) return { status: "rejected", reason: "signature" };
  if (expired(candidate)) return { status: "rejected", reason: "expired" };
  // A device id may not silently change its keys under the same id.
  for (const d of candidate.devices) {
    const old = pinned.devices.find((p) => p.deviceId === d.deviceId);
    if (old && (old.ik !== d.ik || old.ed25519_public_key !== d.ed25519_public_key || old.ml_dsa_public_key !== d.ml_dsa_public_key)) {
      return { status: "rejected", reason: "device_key_changed" };
    }
  }
  const before = new Set(pinned.devices.map((d) => d.deviceId));
  const after = new Set(candidate.devices.map((d) => d.deviceId));
  return {
    status: "changed",
    accepted: candidate,
    added: [...after].filter((id) => !before.has(id)),
    removed: [...before].filter((id) => !after.has(id)),
    approvedBy: candidate.signerDeviceId,
  };
}

/** The devices a sender may encrypt to: exactly the pinned list (never the server's raw rows). */
export function encryptionTargets(pinned: DeviceListStatement): PublicIdentity[] {
  return pinned.devices.slice();
}

/** Receiver side: is this sending device part of the sender's pinned list? */
export function isListedDevice(pinned: DeviceListStatement | null, identity: PublicIdentity): boolean {
  return !!pinned && pinned.devices.some((d) => d.deviceId === identity.deviceId && d.ik === identity.ik && d.ed25519_public_key === identity.ed25519_public_key && d.ml_dsa_public_key === identity.ml_dsa_public_key);
}

/** Re-signs the SAME devices as a new version with a fresh expiry. */
export function refreshDeviceList(current: DeviceListStatement, signer: DeviceIdentitySecrets, now = new Date()): DeviceListStatement {
  return signDeviceList({ signer, userId: current.userId, version: current.version + 1, devices: current.devices, issuedAt: now.toISOString() });
}

/** True once DEVICE_LIST_REFRESH_MS has passed since the list was issued (or it has no expiry). */
export function needsRefresh(current: DeviceListStatement, now = new Date()): boolean {
  return !current.expiresAt || now.getTime() - Date.parse(current.issuedAt) >= DEVICE_LIST_REFRESH_MS;
}

export type GossipVerdict = { status: "consistent" } | { status: "peer_ahead"; version: number } | { status: "peer_behind" } | { status: "equivocation"; version: number };

/**
 * Fork detection (audit E-4). Each party sends, inside its authenticated
 * session, the (version, digest) it has pinned for an account. A different
 * digest for the same version means the server showed different lists to
 * different people: stop and warn. "peer_ahead" means fetch the newer list.
 */
export function compareGossip(pinned: DeviceListStatement, seenByPeer: { version: number; digest: string }): GossipVerdict {
  if (seenByPeer.version === pinned.version) return seenByPeer.digest === deviceListDigest(pinned) ? { status: "consistent" } : { status: "equivocation", version: pinned.version };
  return seenByPeer.version > pinned.version ? { status: "peer_ahead", version: seenByPeer.version } : { status: "peer_behind" };
}
