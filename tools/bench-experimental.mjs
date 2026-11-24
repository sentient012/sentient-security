// Rough cost of the experimental protocols on the machine running it (NOT a phone).
import * as R from "../build-experimental/experimental/ratchet.js";
import * as X from "../build-experimental/experimental/pqxdh.js";
import * as H from "../dist/hybrid-v1/index.js";

const time = (fn, n) => { const t = performance.now(); for (let i = 0; i < n; i++) fn(i); return (performance.now() - t) / n; };
const alice = X.newDeviceIdentity("a", "a1"), bob = X.newDeviceIdentity("b", "b1");
const pre = X.generatePrekeys(bob, { oneTimeCount: 30 });
const INTERVAL = Number(process.env.PQ_INTERVAL || 20);
let init, resp;
const tInit = time((i) => { init = X.initiate({ self: alice, bundle: pre.bundle(i), expectedResponder: X.publicIdentity(bob), plaintext: "hi", pqEpochInterval: INTERVAL }); }, 20);
const tResp = time(() => { resp = X.respond({ self: bob, store: pre.store, message: init.message, expectedInitiator: X.publicIdentity(alice), pqEpochInterval: INTERVAL }); }, 1);
let a = init.state, b = resp.state;
const sizes = [], pq = [];
let tEnc = 0, tDec = 0, n = 200;
for (let i = 0; i < n; i++) {
  const [from, to] = i % 2 ? ["a", "b"] : ["b", "a"];
  const s = { a, b };
  let t = performance.now(); const out = R.encrypt(s[from], "x".repeat(100)); tEnc += performance.now() - t;
  s[from] = out.state;
  t = performance.now(); const back = R.decrypt(s[to], out.message); tDec += performance.now() - t;
  s[to] = back.state; a = s.a; b = s.b;
  const size = Buffer.byteLength(JSON.stringify(out.message)); sizes.push(size); pq.push(R.pqOverheadBytes(out.message));
}
const legacy = H.encryptPayload({ plaintext: "x".repeat(100), threadId: "t", senderUserId: "s", receiverUserId: "r", recipients: [{ id: "d:hybrid-v1", user_id: "r", credential_id: "d", ...(() => { const k = H.deviceKeysFromSecrets(new Uint8Array(32).fill(1), new Uint8Array(64).fill(2)); return { x25519_public_key: Buffer.from(k.x25519PublicKey).toString("base64"), ml_kem_public_key: Buffer.from(k.mlKemPublicKey).toString("base64") }; })() }] });
const tLegacy = time(() => H.encryptPayload({ plaintext: "x".repeat(100), threadId: "t", senderUserId: "s", receiverUserId: "r", recipients: legacy.envelopes.map((e) => ({ id: e.deviceKeyId, user_id: "r", credential_id: "d", x25519_public_key: legacy.envelopes[0].ephemeralX25519PublicKey, ml_kem_public_key: Buffer.from(H.deviceKeysFromSecrets(new Uint8Array(32).fill(1), new Uint8Array(64).fill(2)).mlKemPublicKey).toString("base64") })) }), 20);
const avg = (xs) => Math.round(xs.reduce((s, x) => s + x, 0) / xs.length);
const report = {
  machine: `${process.platform} ${process.arch} node ${process.version}`,
  pqxdh_initiate_ms: +tInit.toFixed(1), pqxdh_respond_ms: +tResp.toFixed(1),
  initial_message_bytes: Buffer.byteLength(JSON.stringify(init.message)),
  ratchet_encrypt_ms_avg: +(tEnc / n).toFixed(2), ratchet_decrypt_ms_avg: +(tDec / n).toFixed(2),
  ratchet_message_bytes_avg: avg(sizes), ratchet_message_bytes_max: Math.max(...sizes), ratchet_message_bytes_min: Math.min(...sizes),
  share_of_messages_carrying_mlkem: +(pq.filter((x) => x > 0).length / n).toFixed(2),
  state_bytes: Buffer.byteLength(JSON.stringify(a)),
  legacy_hybrid_v1_encrypt_one_device_ms: +tLegacy.toFixed(1), legacy_hybrid_v1_one_envelope_bytes: Buffer.byteLength(JSON.stringify(legacy)),
};
console.log(JSON.stringify(report, null, 1));
