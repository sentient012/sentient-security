/*
 * EXPERIMENTAL: signed organization roster (src/experimental/business-roster.ts).
 * Built separately: tsc -p tsconfig.experimental.json
 */
import test from "node:test";
import assert from "node:assert/strict";

import * as B from "../build-experimental/experimental/business-roster.js";
import { kemKeysFromSeeds, newDeviceSeeds, signingKeysFromSeeds, toB64 } from "../build-experimental/business/core.js";

const ORG = "org-1";
function terminal(keyId, businessUserId = `user-${keyId}`) {
  const seeds = newDeviceSeeds();
  const signingKeys = signingKeysFromSeeds(seeds);
  const kem = kemKeysFromSeeds(seeds);
  return { keyId, signer: { keyId, signingKeys }, entry: B.rosterDeviceEntry({ keyId, businessUserId, signingKeys, kemPublic: kem }) };
}
const orgKey = (id, generation = 1) => ({ orgKeyId: id, generation, x25519_public_key: toB64(new Uint8Array(32).fill(generation)), ml_kem_public_key: toB64(new Uint8Array(1184).fill(generation)) });
const sign = (by, version, devices, orgKeys = [], issuedAt) => B.signRoster({ signer: by.signer, organizationId: ORG, version, devices: devices.map((d) => d.entry), orgKeys, issuedAt });

test("first contact pins a self-signed roster; only a listed device can sign the next version", () => {
  const admin = terminal("t-admin"), agent = terminal("t-agent"), rogue = terminal("t-rogue");
  const v1 = sign(admin, 1, [admin], [orgKey("ok-1")]);
  const first = B.evaluateRoster(null, v1);
  assert.equal(first.status, "first_seen");
  const v2 = sign(admin, 2, [admin, agent], [orgKey("ok-1")]);
  const changed = B.evaluateRoster(v1, v2);
  assert.equal(changed.status, "changed");
  assert.deepEqual(changed.added, ["t-agent"]);
  // The server (or anyone) adds a device without an authorized signature: an identity reset, never silent.
  const forged = sign(rogue, 3, [admin, agent, rogue], [orgKey("ok-1")]);
  assert.equal(B.evaluateRoster(v2, forged).status, "identity_reset");
  // Signing as an authorized device with another key fails outright.
  const impostor = B.signRoster({ signer: { keyId: "t-admin", signingKeys: rogue.signer.signingKeys }, organizationId: ORG, version: 3, devices: [admin.entry, rogue.entry], orgKeys: [] });
  assert.equal(B.evaluateRoster(v2, impostor).status, "rejected");
});

test("rollback, equivocation, gaps, expiry and freezing are detected", () => {
  const admin = terminal("t-admin"), agent = terminal("t-agent");
  const v1 = sign(admin, 1, [admin]);
  const v2 = sign(admin, 2, [admin, agent]);
  assert.equal(B.evaluateRoster(v2, v1).status, "stale");
  const v2b = sign(admin, 2, [admin]);
  assert.deepEqual(B.evaluateRoster(v2, v2b), { status: "rejected", reason: "equivocation" });
  const v4 = sign(admin, 4, [admin]);
  assert.deepEqual(B.evaluateRoster(v2, v4), { status: "rejected", reason: "gap" });
  const later = new Date(Date.now() + B.ROSTER_LIFETIME_MS + 1000);
  assert.deepEqual(B.evaluateRoster(v2, v2, { now: later }), { status: "rejected", reason: "frozen" });
  assert.deepEqual(B.evaluateRoster(null, v1, { now: later }), { status: "rejected", reason: "expired" });
  assert.equal(B.rosterNeedsRefresh(v2, new Date(Date.now() + B.ROSTER_REFRESH_MS + 1000)), true);
  const v3 = B.refreshRoster(v2, admin.signer);
  assert.equal(B.evaluateRoster(v2, v3).status, "changed");
  assert.deepEqual(B.evaluateRoster(v1, sign(admin, 2, [admin]), { organizationId: "org-2" }), { status: "rejected", reason: "organization" });
});

test("a chain is followed version by version; a device removed earlier cannot sign later", () => {
  const admin = terminal("t-admin"), agent = terminal("t-agent"), other = terminal("t-other");
  const v1 = sign(admin, 1, [admin, agent]);
  const v2 = sign(admin, 2, [admin]);            // agent removed
  const v3 = sign(agent, 3, [admin, agent, other]); // signed by the removed agent
  const walk = B.evaluateRosterChain(v1, [v3, v2]);
  assert.equal(walk.accepted.version, 2);
  assert.equal(walk.stopped.status, "identity_reset");
  const ok = B.evaluateRosterChain(null, [v2, v1, sign(admin, 3, [admin, other])]);
  assert.equal(ok.accepted.version, 3);
  assert.equal(ok.stopped, null);
  assert.deepEqual(ok.history.map((s) => s.version), [1, 2, 3]);
});

test("the roster filters the server's recipients and signing keys", () => {
  const admin = terminal("t-admin"), agent = terminal("t-agent"), left = terminal("t-left");
  const v1 = sign(admin, 1, [admin, agent, left], [orgKey("ok-1")]);
  const v2 = sign(admin, 2, [admin, agent], [orgKey("ok-1")]);
  const rec = (t) => ({ kind: "terminal_device", key_id: t.keyId, x25519_public_key: t.entry.x25519_public_key, ml_kem_public_key: t.entry.ml_kem_public_key });
  const sk = (t) => ({ kind: "terminal_device", key_id: t.keyId, ed25519_public_key: t.entry.ed25519_public_key, ml_dsa_public_key: t.entry.ml_dsa_public_key });
  const injected = terminal("t-server");
  const state = {
    organization_id: ORG,
    required_recipients: [
      { kind: "consumer_device", key_id: "c1", x25519_public_key: "x", ml_kem_public_key: "y" },
      rec(admin), rec(agent), rec(left), rec(injected),
      { ...rec(agent), x25519_public_key: injected.entry.x25519_public_key },                  // substituted encryption key
      { kind: "org_access", key_id: "ok-1", x25519_public_key: orgKey("ok-1").x25519_public_key, ml_kem_public_key: orgKey("ok-1").ml_kem_public_key },
      { kind: "org_access", key_id: "ok-server", x25519_public_key: "a", ml_kem_public_key: "b" },
    ],
    signing_keys: [{ kind: "consumer_device", key_id: "c1" }, sk(admin), sk(left), sk(injected), { ...sk(agent), ml_dsa_public_key: injected.entry.ml_dsa_public_key }],
  };
  const { state: out, excluded } = B.rosterFilterState(state, v2, [v1, v2]);
  assert.deepEqual(out.required_recipients.map((r) => `${r.kind}:${r.key_id}`), ["consumer_device:c1", "terminal_device:t-admin", "terminal_device:t-agent", "org_access:ok-1"]);
  assert.deepEqual(out.signing_keys.map((r) => `${r.kind}:${r.key_id}`), ["consumer_device:c1", "terminal_device:t-admin", "terminal_device:t-left"], "a former employee's messages stay verifiable");
  assert.ok(excluded.some((e) => e.key_id === "t-server"));
  assert.throws(() => B.rosterFilterState({ ...state, organization_id: "org-2" }, v2), /organization/);
});

test("malformed rosters are rejected before any signature work", () => {
  const admin = terminal("t-admin");
  const v1 = sign(admin, 1, [admin]);
  assert.deepEqual(B.evaluateRoster(null, { ...v1, devices: [] }), { status: "rejected", reason: "shape" });
  assert.deepEqual(B.evaluateRoster(null, { ...v1, devices: [{ ...v1.devices[0], keyId: "" }] }), { status: "rejected", reason: "shape" });
  assert.deepEqual(B.evaluateRoster(null, { ...v1, version: 0 }), { status: "rejected", reason: "shape" });
  assert.deepEqual(B.evaluateRoster(null, { ...v1, devices: [{ ...v1.devices[0], businessUserId: "someone-else" }] }), { status: "rejected", reason: "signature" });
  assert.throws(() => sign(admin, 1, [admin, admin]), /Duplicate/);
});
