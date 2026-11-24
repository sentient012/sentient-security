#!/usr/bin/env node
/*
 * Captures legacy-parity vectors by running test/scenarios.mjs against the
 * UNMODIFIED Sentient sources (private repositories; not part of this
 * package). Usage:
 *
 *   node tools/capture-legacy-vectors.cjs <sentient-app dir> <sentient-website dir>
 *
 * Writes test/vectors/legacy-vectors.json, recording the source commit and
 * the SHA-256 of every source file that was executed, so a reviewer with
 * access to those commits can re-run the capture. Only test-only keys
 * derived from a public seed appear in the output.
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { pathToFileURL } = require("node:url");
const { execFileSync } = require("node:child_process");

const [appDir, siteDir] = process.argv.slice(2).map((p) => p && path.resolve(p));
if (!appDir || !siteDir) {
  console.error("usage: capture-legacy-vectors.cjs <sentient-app dir> <sentient-website dir>");
  process.exit(2);
}

const lib = (p) => path.join(appDir, p);
const { loadTsMocked } = require(lib("tests/helpers/load-ts-mocked.cjs"));
const { loadTs } = require(lib("tests/helpers/load-ts.cjs"));

function gitHead(dir) {
  try {
    return execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}
function gitDirty(dir, files) {
  try {
    return execFileSync("git", ["-C", dir, "status", "--porcelain", "--", ...files], { encoding: "utf8" }).trim();
  } catch {
    return "unknown";
  }
}
const sha = (file) => crypto.createHash("sha256").update(fs.readFileSync(file).toString("utf8").replace(/\r\n/g, "\n")).digest("hex");

(async () => {
  const scenarios = await import(pathToFileURL(path.join(__dirname, "..", "test", "scenarios.mjs")).href);
  const { deterministicRandom } = await import(pathToFileURL(path.join(__dirname, "..", "dist", "testing", "index.js")).href);
  const { base64 } = require(lib("node_modules/@scure/base"));

  let currentRand = null;
  const expoCrypto = {
    getRandomBytes: (n) => {
      if (!currentRand) throw new Error("no deterministic source installed");
      return currentRand(n);
    },
  };
  const secure = new Map();
  const secureStore = {
    getItemAsync: async (k) => (secure.has(k) ? secure.get(k) : null),
    setItemAsync: async (k, v) => void secure.set(k, v),
    deleteItemAsync: async (k) => void secure.delete(k),
  };

  // --- legacy sentient-hybrid-v1 (lib/e2ee.ts) --------------------------------
  let bundlesForQuery = [];
  const supabase = {
    from(table) {
      const q = {
        upsert: async () => ({ error: null }),
        select() { return q; },
        in() { return q; },
        eq() { return q; },
        order: async () => ({ data: bundlesForQuery, error: null }),
      };
      if (table !== "device_e2ee_keys") throw new Error(`unexpected table ${table}`);
      return q;
    },
    rpc: async () => ({ data: null, error: null }),
  };
  function loadE2ee() {
    return loadTsMocked(lib("lib/e2ee.ts"), {
      "expo-crypto": expoCrypto,
      "expo-secure-store": secureStore,
      [lib("lib/analytics-bus.ts")]: { track() {} },
      [lib("lib/supabase.ts")]: { supabase },
      [lib("lib/e2ee-keyring-store.ts")]: null,
    });
  }
  async function asDevice(device, fn) {
    secure.clear();
    secure.set("sentient_user_id", device.userId);
    secure.set("sentient_credential_id", device.credentialId);
    secure.set(`sentient_e2ee_x25519_private_v1.${device.credentialId}`, base64.encode(device.x25519PrivateKey));
    secure.set(`sentient_e2ee_mlkem_seed_v1.${device.credentialId}`, base64.encode(device.mlKemSeed));
    return fn(loadE2ee()); // fresh module graph = fresh caches
  }
  const legacyHybrid = {
    encrypt: (p) =>
      asDevice(p.senderDevice, (e2ee) => {
        bundlesForQuery = p.recipients;
        return e2ee.encryptMessageForConversation({ plaintext: p.plaintext, threadId: p.threadId, senderUserId: p.senderUserId, receiverUserId: p.receiverUserId });
      }),
    decrypt: (payload, device) =>
      asDevice(device, (e2ee) => e2ee.decryptMessageRecord({ id: "m", thread_id: payload.threadId, sender_user_id: payload.senderUserId, receiver_user_id: payload.receiverUserId, body: null, e2ee_payload: payload, created_at: "2026-11-23T12:00:00.000Z" }, device.userId)),
  };

  // --- legacy pure modules ----------------------------------------------------
  const business = loadTs(lib("lib/business/crypto/business-crypto-core.js"));
  const group = loadTs(lib("lib/group/group-crypto-core.js"));
  const keyring = loadTs(lib("lib/e2ee-keyring.ts"));
  const recovery = loadTs(lib("lib/e2ee-recovery.ts"));
  const passkey = loadTsMocked(lib("lib/passkey-recovery-crypto.ts"), { "expo-crypto": expoCrypto });
  const preview = loadTs(lib("lib/notification-preview-crypto.js"));
  const callModule = loadTsMocked(lib("lib/calling-pqc.ts"), {
    "expo-crypto": expoCrypto,
    "expo-secure-store": secureStore,
    [lib("lib/supabase.ts")]: { supabase },
  });
  const frame = await import(pathToFileURL(path.join(siteDir, "src/terminal/crypto/frameCrypto.js")).href);
  const terminalCall = await import(pathToFileURL(path.join(siteDir, "src/terminal/crypto/callPqcHandshake.js")).href);
  const { ed25519 } = require(lib("node_modules/@noble/curves/ed25519.js"));
  const { ml_dsa65 } = require(lib("node_modules/@noble/post-quantum/ml-dsa.js"));

  const legacyCall = {
    Handshake: callModule.CallPqcHandshake,
    extractDtlsFingerprints: callModule.extractDtlsFingerprints,
    async makeIdentity(credentialId, edSeed, mlDsaSeed) {
      secure.set(`sentient_call_sign_ed25519_v1.${credentialId}`, base64.encode(edSeed));
      secure.set(`sentient_call_sign_mldsa_seed_v1.${credentialId}`, base64.encode(mlDsaSeed));
      return callModule.getOrCreateDeviceSigningIdentity(credentialId);
    },
  };

  const impl = { hybrid: legacyHybrid, business, group, keyring, recovery, passkey, preview, call: legacyCall, frame };
  const setImplRandom = (r) => {
    currentRand = r;
  };

  const run = async (name, fn) => {
    const rand = deterministicRandom(`${scenarios.SCENARIO_SEED} / ${name}`);
    const value = await scenarios.withDeterminism(rand, setImplRandom, () => fn(rand));
    return { value, randomBytesConsumed: rand.consumed };
  };
  const out = {};
  out.hybrid = await run("hybrid", (rand) => scenarios.hybridScenario(impl, rand));
  out.business = await run("business", () => scenarios.businessScenario(impl));
  out.group = await run("group", () => scenarios.groupScenario(impl));
  out.preview = { value: scenarios.previewScenario(impl, out.hybrid.value, out.group.value) };
  out.recovery = await run("recovery", (rand) => scenarios.recoveryScenario(impl, rand));
  out.call = await run("call", (rand) => scenarios.callScenario(impl, rand));
  out.frame = await run("frame", (rand) => scenarios.frameScenario(impl, rand));
  // The Business Terminal's own handshake implementation, same scenario and stream.
  const terminalImpl = {
    call: {
      Handshake: terminalCall.TerminalCallPqcHandshake,
      extractDtlsFingerprints: terminalCall.extractDtlsFingerprints,
      async makeIdentity(credentialId, edSeed, mlDsaSeed) {
        const dsa = ml_dsa65.keygen(mlDsaSeed);
        return { credentialId, deviceKeyId: `${credentialId}:call-sign-v1`, ed25519PrivateKey: edSeed, ed25519PublicKey: ed25519.getPublicKey(edSeed), mlDsaSeed, mlDsaSecretKey: dsa.secretKey, mlDsaPublicKey: dsa.publicKey };
      },
    },
  };
  out.callTerminal = await run("call", (rand) => scenarios.callScenario(terminalImpl, rand));

  const appFiles = ["lib/e2ee.ts", "lib/business/crypto/business-crypto-core.js", "lib/group/group-crypto-core.js", "lib/e2ee-keyring.ts", "lib/e2ee-recovery.ts", "lib/passkey-recovery-crypto.ts", "lib/notification-preview-crypto.js", "lib/calling-pqc.ts"];
  const siteFiles = ["src/terminal/crypto/frameCrypto.js", "src/terminal/crypto/callPqcHandshake.js"];
  const doc = {
    note: "TEST ONLY. Captured from deployed Sentient sources with a public deterministic seed. Do not use these keys for anything.",
    seed: scenarios.SCENARIO_SEED,
    fixedTime: new Date(scenarios.FIXED_TIME_MS).toISOString(),
    sources: {
      "sentient-app": { commit: gitHead(appDir), dirty: gitDirty(appDir, appFiles) || "clean", files: Object.fromEntries(appFiles.map((f) => [f, sha(lib(f))])) },
      "sentient-website": { commit: gitHead(siteDir), dirty: gitDirty(siteDir, siteFiles) || "clean", files: Object.fromEntries(siteFiles.map((f) => [f, sha(path.join(siteDir, f))])) },
    },
    vectors: out,
  };
  const target = path.join(__dirname, "..", "test", "vectors", "legacy-vectors.json");
  fs.writeFileSync(target, JSON.stringify(doc, null, 1) + "\n");
  console.log(`wrote ${target} (${fs.statSync(target).size} bytes)`);
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
