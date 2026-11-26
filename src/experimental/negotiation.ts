/*
 * NOT REVIEWED. Off unless the app enables it (see EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT).
 *
 * Protocol selection and downgrade protection between sentient-hybrid-v1
 * (deployed) and the session protocol (sentient-pqxdh-v0 key agreement +
 * sentient-tr-v0 ratchet; one suite, either id in a SIGNED capability list
 * selects it).
 *
 * Rules:
 *   1. The new protocol is used only when the feature flag is on locally AND
 *      the peer device's SIGNED capabilities (prekey bundle) list the suite.
 *   2. Once a session with the stronger protocol has been established with a
 *      peer ACCOUNT, the pair is "upgraded" (pinned per account: hybrid-v1
 *      messages carry no sender authentication, so the "device" a legacy
 *      message claims is only the server's word).
 *        - Sending: an upgraded pin NEVER falls back to hybrid-v1. If the
 *          server withholds, strips or corrupts the peer's bundle, selection
 *          returns "blocked" and the app must refuse to send (audit E-2).
 *        - Receiving: a later legacy message from that account is not
 *          accepted silently: shown as a downgrade, never as authenticated.
 *   3. "Upgraded" is cleared only by an explicit, user-visible session reset,
 *      such as the peer's identity reset (device-list.ts) followed by
 *      re-verification (clearUpgrade).
 *   4. Nothing switches on by default: EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT is false.
 */
import { RATCHET_PROTOCOL } from "./ratchet.js";

export const LEGACY_PROTOCOL = "sentient-hybrid-v1" as const;
/** The key-agreement id. A bundle signing either id offers the whole suite (pqxdh initial message + tr-v0 session). */
export const SESSION_KEY_AGREEMENT = "sentient-pqxdh-v0-experimental" as const;
export const SESSION_SUITE_IDS: readonly string[] = [SESSION_KEY_AGREEMENT, RATCHET_PROTOCOL];
export const EXPERIMENTAL_PROTOCOLS_ENABLED_DEFAULT = false as const;

export type PeerProtocolState = { peerUserId: string; upgraded: boolean; upgradedAt?: string; clearedAt?: string };

/** Does a signed capability list offer the session suite? (audit E-1: either id counts; both are signed together by default.) */
export function offersSessionSuite(peerSignedProtocols: readonly string[] | null | undefined): boolean {
  return !!peerSignedProtocols && peerSignedProtocols.some((p) => SESSION_SUITE_IDS.includes(p));
}

export type Selection = typeof RATCHET_PROTOCOL | typeof LEGACY_PROTOCOL | "blocked";

/**
 * Which protocol to SEND with.
 *   pin: the per-account upgrade state. If it says upgraded, the result is the
 *   ratchet or "blocked" - never legacy, whatever the server returned.
 */
export function selectProtocol(params: { localEnabled: boolean; peerSignedProtocols: readonly string[] | null; pin?: PeerProtocolState | null }): Selection {
  const offered = offersSessionSuite(params.peerSignedProtocols);
  if (params.pin?.upgraded) return offered ? RATCHET_PROTOCOL : "blocked";
  if (params.localEnabled && offered) return RATCHET_PROTOCOL;
  return LEGACY_PROTOCOL;
}

/** peerId: the peer ACCOUNT (user id). */
export function markUpgraded(peerId: string, at = new Date().toISOString()): PeerProtocolState {
  return { peerUserId: peerId, upgraded: true, upgradedAt: at };
}

/** Only after a user-visible reset (identity reset acknowledged, or keys re-verified). */
export function clearUpgrade(state: PeerProtocolState, at = new Date().toISOString()): PeerProtocolState {
  return { peerUserId: state.peerUserId, upgraded: false, clearedAt: at };
}

export type IncomingVerdict = { accept: true; label: "ratchet_authenticated" | "legacy" } | { accept: false; reason: "downgrade" | "unknown_protocol" };

/** How an incoming message from a peer account must be treated given the pair's protocol state. */
export function classifyIncoming(state: PeerProtocolState | null, protocol: string): IncomingVerdict {
  if (protocol === RATCHET_PROTOCOL || protocol === SESSION_KEY_AGREEMENT) return { accept: true, label: "ratchet_authenticated" };
  if (protocol === LEGACY_PROTOCOL) return state?.upgraded ? { accept: false, reason: "downgrade" } : { accept: true, label: "legacy" };
  return { accept: false, reason: "unknown_protocol" };
}
