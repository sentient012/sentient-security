/*
 * Time at which a signing-key revocation check is evaluated.
 *
 * Wraps and key links carry a createdAt INSIDE the signed object: whoever
 * holds the signing key chooses it, including after the key was revoked
 * (backdating). The server row's created_at is recorded by the backend at
 * insert. Rule: when the server supplies a time, use the LATER of the two
 * (the stricter one: a revocation check rejects at >= revoked_at); when it
 * supplies none (backends that do not return it yet), fall back to the
 * claimed time, which is the deployed behaviour.
 *
 * The backend already refuses new wraps/links from revoked keys
 * (private.group_key_belongs), so this is defence in depth against a
 * dishonest server or a direct database write. It can only make acceptance
 * stricter, never wider.
 */
function parseTime(value) {
  const t = Date.parse(value || "");
  return Number.isFinite(t) ? t : null;
}

export function trustedTime(serverTime, claimedTime) {
  const server = parseTime(serverTime);
  if (server === null) return claimedTime;
  const claimed = parseTime(claimedTime);
  return claimed !== null && claimed > server ? claimedTime : serverTime;
}
