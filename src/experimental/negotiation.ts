/*
 * EXPERIMENTAL - NOT REVIEWED - NOT USED BY ANY SENTIENT CLIENT.
 *
 * Protocol selection and downgrade protection between sentient-hybrid-v1
 * (deployed) and sentient-tr-v0-experimental.
 *
 * Rules:
 *   1. The new protocol is used only when the feature flag is on locally AND
 *      the peer device's SIGNED capabilities (prekey bundle) list it.
 *   2. Once a session with the stronger protocol has been established with a
 *      peer device, the pair is "upgraded": a later legacy message from that
 *      device is NOT accepted silently. The app must show it as a downgrade
 *      and must not label it as end-to-end authenticated.
 *   3. "Upgraded" is cleared only by an explicit, user-visible session reset,
 *      such as the peer's identity reset (device-list.ts) followed by
 *      re-verification.
 *   4. Nothing switches on by default: EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT is false.
 */
import { RATCHET_PROTOCOL } from "./ratchet.js";

export const LEGACY_PROTOCOL = "sentient-hybrid-v1" as const;
export const EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT = false as const;

export type PeerProtocolState = { peerDeviceId: string; upgraded: boolean; upgradedAt?: string };

export function selectProtocol(params: { localEnabled: boolean; peerSignedProtocols: string[] | null }): typeof RATCHET_PROTOCOL | typeof LEGACY_PROTOCOL {
  if (params.localEnabled && params.peerSignedProtocols?.includes(RATCHET_PROTOCOL)) return RATCHET_PROTOCOL;
  return LEGACY_PROTOCOL;
}

export function markUpgraded(peerDeviceId: string, at = new Date().toISOString()): PeerProtocolState {
  return { peerDeviceId, upgraded: true, upgradedAt: at };
}

export type IncomingVerdict = { accept: true; label: "ratchet_authenticated" | "legacy" } | { accept: false; reason: "downgrade" | "unknown_protocol" };

/** How an incoming message from a peer device must be treated given the pair's protocol state. */
export function classifyIncoming(state: PeerProtocolState | null, protocol: string): IncomingVerdict {
  if (protocol === RATCHET_PROTOCOL) return { accept: true, label: "ratchet_authenticated" };
  if (protocol === LEGACY_PROTOCOL) return state?.upgraded ? { accept: false, reason: "downgrade" } : { accept: true, label: "legacy" };
  return { accept: false, reason: "unknown_protocol" };
}
