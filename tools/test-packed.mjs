// Packs the package, installs the TARBALL into a fresh temporary project and
// runs the full test suite against the installed copy (not the source tree).
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const sh = (cmd, args, cwd) => execFileSync(cmd, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
const root = resolve(".");
sh("npm", ["run", "build"], root);
const packDir = mkdtempSync(join(tmpdir(), "sentient-security-pack-"));
sh("npm", ["pack", "--ignore-scripts", "--pack-destination", packDir], root);
const tarball = join(packDir, readdirSync(packDir).find((f) => f.endsWith(".tgz")));
const project = mkdtempSync(join(tmpdir(), "sentient-security-consumer-"));
writeFileSync(join(project, "package.json"), JSON.stringify({ name: "consumer", private: true, type: "module" }));
sh("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], project);
mkdirSync(join(project, "test"));
for (const f of ["legacy-parity.test.mjs", "negative.test.mjs", "scenarios.mjs"]) cpSync(join(root, "test", f), join(project, "test", f));
cpSync(join(root, "test", "vectors"), join(project, "test", "vectors"), { recursive: true });
// negative.test.mjs reaches into dist/internal for one helper; map it to the installed package.
mkdirSync(join(project, "dist", "internal"), { recursive: true });
writeFileSync(join(project, "dist", "internal", "time.js"), 'export * from "../../node_modules/@sentient012/security/dist/internal/time.js";\n');
try {
  sh("node", ["--test", "test/legacy-parity.test.mjs", "test/negative.test.mjs"], project);
  console.log(`packed-package tests passed against ${tarball}`);
} finally {
  rmSync(project, { recursive: true, force: true });
}
