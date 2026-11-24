// Repository secret scan (tracked + untracked, excluding node_modules/dist).
// Fails on private keys, cloud/API tokens, JWTs, Sentient infrastructure
// identifiers and high-entropy assignments to secret-looking names.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const files = execFileSync("git", ["-c", "safe.directory=*", "ls-files", "--cached", "--others", "--exclude-standard"], { encoding: "utf8" }).split("\n").filter(Boolean);
const rules = [
  ["private key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ["JWT", /eyJhbGciOi[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./],
  ["Stripe live key", /sk_live_[0-9a-zA-Z]{10,}/],
  ["AWS key", /AKIA[0-9A-Z]{16}/],
  ["GitHub token", /gh[pousr]_[A-Za-z0-9]{30,}/],
  ["npm token", /npm_[A-Za-z0-9]{30,}/],
  ["Google API key", /AIza[0-9A-Za-z_-]{35}/],
  ["Supabase project", /[a-z]{20}\.supabase\.co/],
  ["secret assignment", /(secret|password|passwd|api[_-]?key|token)["']?\s*[:=]\s*["'][A-Za-z0-9+/_-]{24,}["']/i],
];
const allow = new Set(["tools/scan-secrets.mjs", "tools/verify-pack.mjs"]);
let failed = 0;
for (const f of files) {
  if (allow.has(f) || /\.(png|jpg|tgz)$/.test(f)) continue;
  const text = readFileSync(f, "utf8");
  for (const [name, re] of rules) {
    const m = re.exec(text);
    if (m) {
      failed++;
      console.error(`${f}: ${name} at offset ${m.index}`);
    }
  }
}
console.log(`scanned ${files.length} files: ${failed ? failed + " finding(s)" : "no findings"}`);
process.exit(failed ? 1 : 0);
