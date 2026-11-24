/*
 * EXPERIMENTAL - NOT REVIEWED - NOT USED BY ANY SENTIENT CLIENT.
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
 *   - peers pin the last accepted list per account and classify every new one
 *     as unchanged / devices added / devices removed / identity reset;
 *   - an "identity reset" (no listed device can sign, e.g. every device was
 *     lost and the account was recovered) is never accepted silently: the app
 *     must show it and should require re-verification.
 *
 * This is the "sender-side device-list verification" foundation: the sender
 * encrypts only to devices in the pinned list, and the receiver of a session
 * checks the sending device is in the sender's pinned list.
 *
 * Sentient specifics: account recovery (recovery phrase + PIN, or passkey)
 * makes a NEW device without any old one. That is exactly the identity-reset
 * case, and it is surfaced, not hidden. Business Terminal devices are not
 * consumer devices; a business's devices belong in a separate,
 * organization-scoped list and must never appear in a consumer's list.
 */
import { signHybrid, verifyHybrid } from "../business/core.js";
import type { PublicIdentity } from "./pqxdh.js";
import { signingKeysOf, verifyPublicIdentity, type DeviceIdentitySecrets } from "./pqxdh.js";

export const DEVICE_LIST_PROTOCOL = "sentient-device-list-v0-experimental" as const;
const CONTEXT = `${DEVICE_LIST_PROTOCOL}/statement`;
export const MAX_DEVICES = 32;

export type DeviceListStatement = {
  v: typeof DEVICE_LIST_PROTOCOL;
  userId: string;
  version: number;
  devices: PublicIdentity[];
  issuedAt: string;
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
  return { v: s.v, userId: s.userId, version: s.version, devices: s.devices, issuedAt: s.issuedAt, signerDeviceId: s.signerDeviceId };
}

/** Signs a new list. The signer must be in `devices` (it approves the result). */
export function signDeviceList(params: { signer: DeviceIdentitySecrets; userId: string; version: number; devices: PublicIdentity[]; issuedAt?: string }): DeviceListStatement {
  if (!Number.isSafeInteger(params.version) || params.version < 1) throw new DeviceListError("version");
  if (params.devices.length === 0 || params.devices.length > MAX_DEVICES) throw new DeviceListError("device_count");
  const ids = new Set(params.devices.map((d) => d.deviceId));
  if (ids.size !== params.devices.length) throw new DeviceListError("duplicate_device");
  if (!ids.has(params.signer.deviceId)) throw new DeviceListError("signer_not_listed");
  const unsigned = { v: DEVICE_LIST_PROTOCOL, userId: params.userId, version: params.version, devices: params.devices, issuedAt: params.issuedAt ?? new Date().toISOString(), signerDeviceId: params.signer.deviceId } as const;
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
  | { status: "rejected"; reason: string };

/**
 * Compare a newly fetched list with the pinned one.
 *   first_seen     - nothing pinned: accepted on trust-on-first-use (the app should
 *                    offer verification, see identity-verification.ts)
 *   unchanged      - same version and contents
 *   changed        - newer version signed by a device in the pinned list
 *   identity_reset - newer version NOT signed by any pinned device: do not
 *                    accept silently; require the user to re-verify
 *   rejected       - invalid, rolled back, or the same version with other contents
 */
export function evaluateDeviceList(pinned: DeviceListStatement | null, candidate: DeviceListStatement): DeviceListVerdict {
  if (!candidate || candidate.v !== DEVICE_LIST_PROTOCOL) return { status: "rejected", reason: "version" };
  const signer = candidate.devices.find((d) => d.deviceId === candidate.signerDeviceId);
  if (!signer) return { status: "rejected", reason: "signer_not_listed" };
  if (!pinned) {
    return verifyStatement(candidate, signer) ? { status: "first_seen", accepted: candidate } : { status: "rejected", reason: "signature" };
  }
  if (candidate.userId !== pinned.userId) return { status: "rejected", reason: "wrong_account" };
  if (candidate.version < pinned.version) return { status: "rejected", reason: "rollback" };
  if (candidate.version === pinned.version) {
    return JSON.stringify(body(candidate)) === JSON.stringify(body(pinned)) && candidate.signature.ed25519 === pinned.signature.ed25519
      ? { status: "unchanged", accepted: pinned }
      : { status: "rejected", reason: "equivocation" };
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
