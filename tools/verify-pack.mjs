// Builds the tarball and checks its exact contents: an allowlist of paths, no
// source maps of private paths, no test vectors/tools, no secrets-looking text.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

execFileSync("npm", ["run", "build"], { stdio: "inherit", shell: process.platform === "win32" });
const out = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], { encoding: "utf8", shell: process.platform === "win32" });
const [info] = JSON.parse(out);
const files = info.files.map((f) => f.path).sort();
// src/ is shipped on purpose: reviewers can read the exact source next to the build output.
const allowed = [
  /^dist\/[a-z0-9-]+(\/[a-z0-9-]+)*\.(js|d\.ts)$/,
  /^src\/(?!experimental\/|testing\/.*vector)[a-z0-9-]+(\/[a-z0-9-]+)*\.(js|ts)$/,
  /^(LICENSE|NOTICE|README\.md|SECURITY\.md|THREAT_MODEL\.md|PROTOCOLS\.md|CHANGELOG\.md|THIRD_PARTY_NOTICES\.md|RESEARCHERS\.md|package\.json)$/,
];
const bad = files.filter((f) => !allowed.some((re) => re.test(f)));
const forbidden = files.filter((f) => /experimental|testing\/.*vector|\.env|\.pem|\.key$|\.tgz$/.test(f));
const secretRe = /(BEGIN [A-Z ]*PRIVATE KEY|sk_live_|eyJhbGciOi[A-Za-z0-9_-]{20,}\.|AKIA[0-9A-Z]{16}|webhook-secret|[a-z]{20}\.supabase\.co|service_role)/;
const leaky = files.filter((f) => secretRe.test(readFileSync(f, "utf8")));
console.log(`${info.name}@${info.version}: ${files.length} files, ${info.size} bytes packed, ${info.unpackedSize} unpacked`);
console.log(`integrity ${info.integrity}\nshasum ${info.shasum}`);
for (const f of files) console.log("  " + f);
if (bad.length || forbidden.length || leaky.length) {
  console.error({ notAllowlisted: bad, forbidden, secretLookingContent: leaky });
  process.exit(1);
}
