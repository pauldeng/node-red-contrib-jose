#!/usr/bin/env node
// Local package sanity checks; --release adds publication metadata requirements.
// Source heuristics are advisory; this is not the official Flow Library scorecard
// or a substitute for actual loading, credential-export, and clean-install tests.
// Usage: node check-package.mjs [package-dir]   (exit 1 on any FAIL; WARN never fails)
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve, basename } from "node:path";
import { execFileSync } from "node:child_process";

const release = process.argv.includes("--release");
const dir = resolve(process.argv.slice(2).find((a) => !a.startsWith("--")) ?? ".");
const out = { fail: [], warn: [], pass: [] };
const fail = (id, m) => out.fail.push(`${id} ${m}`);
const warn = (id, m) => out.warn.push(`${id} ${m}`);
const pass = (id, m) => out.pass.push(`${id} ${m}`);

const pkgPath = join(dir, "package.json");
if (!existsSync(pkgPath)) {
  console.error(`no package.json in ${dir}`);
  process.exit(2);
}
const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));

// ---- package.json (scorecard P-rules) --------------------------------------
if (release) {
  if (pkg.private) fail("PKG", "private package cannot be published");
  pkg.license ? pass("P01", `license ${pkg.license}`) : fail("P01", "package.json needs a license (SPDX id)");
  pkg.repository || pkg.bugs
    ? pass("P03", "repository/bugs present")
    : fail("P03", "package.json needs repository or bugs");
  /^@[^/]+\//.test(pkg.name ?? "")
    ? pass("P04", `scoped name ${pkg.name}`)
    : fail("P04", "new public packages should use a scoped name (@scope/name)");
  for (const file of ["README.md", "LICENSE"]) if (!existsSync(join(dir, file))) fail("PKG", `${file} missing`);
}
(pkg.keywords ?? []).includes("node-red")
  ? pass("P05", "keyword node-red")
  : fail("P05", 'keywords must include "node-red"');
const nrVersion = pkg["node-red"]?.version;
nrVersion ? pass("P06", `node-red.version ${nrVersion}`) : warn("P06", 'declare node-red.version (e.g. ">=5.0.0")');

const nodeEngine = pkg.engines?.node;
nodeEngine ? pass("P07", `engines.node ${nodeEngine}`) : warn("P07", "declare the supported Node.js range");
const depCount = Object.keys(pkg.dependencies ?? {}).length;
depCount > 6
  ? warn("D01", `${depCount} runtime dependencies (scorecard warns above 6)`)
  : pass("D01", `${depCount} runtime dependencies`);

pkg.main && !existsSync(join(dir, pkg.main)) && fail("PKG", `main ${pkg.main} does not exist`);

// ---- node-red.nodes -> files, registerType names, help, credentials ----------
const nodes = pkg["node-red"]?.nodes ?? {};
Object.keys(nodes).length
  ? pass("NODES", `${Object.keys(nodes).length} entry file(s)`)
  : fail("NODES", "node-red.nodes is empty");
const registered = new Set();
for (const [key, rel] of Object.entries(nodes)) {
  const js = join(dir, rel);
  if (!existsSync(js)) {
    fail("NODES", `${key}: ${rel} missing`);
    continue;
  }
  const html = js.replace(/\.js$/, ".html");
  if (!existsSync(html)) {
    fail("EDITOR", `${key}: no ${basename(html)} next to ${rel}`);
    continue;
  }
  const jsSrc = readFileSync(js, "utf8"),
    htmlSrc = readFileSync(html, "utf8");
  const rtTypes = [...jsSrc.matchAll(/registerType\(\s*["'`]([^"'`]+)["'`]/g)].map((m) => m[1]);
  const edTypes = [...htmlSrc.matchAll(/RED\.nodes\.registerType\(\s*["'`]([^"'`]+)["'`]/g)].map((m) => m[1]);
  const templates = [...htmlSrc.matchAll(/data-template-name=["']([^"']+)["']/g)].map((m) => m[1]);
  const helps = [...htmlSrc.matchAll(/data-help-name=["']([^"']+)["']/g)].map((m) => m[1]);
  for (const t of rtTypes) {
    registered.add(t);
    edTypes.includes(t)
      ? pass("TYPE", `${t}: runtime+editor registered`)
      : fail("TYPE", `${t}: registered in ${rel} but not in ${basename(html)}`);
    templates.includes(t) || fail("EDITOR", `${t}: no <script data-template-name="${t}">`);
    helps.includes(t)
      ? pass("HELP", `${t}: help present`)
      : fail("HELP", `${t}: no <script data-help-name="${t}"> (scorecard + users need it)`);
  }
  for (const t of edTypes)
    rtTypes.includes(t) || fail("TYPE", `${t}: registered in ${basename(html)} but not in ${rel}`);
  /type=["']text\/x-red["']/.test(htmlSrc) &&
    warn(
      "EDITOR",
      `${basename(html)}: text/x-red is a legacy alias still parsed by Node-RED 5; new code uses text/html (template) and text/html or text/markdown (help)`,
    );
  /fa-(layer-group|circle-notch|stream|network-wired)\b/.test(htmlSrc) &&
    warn("ICON", `${basename(html)}: uses a Font Awesome 5+ icon name; Node-RED ships FA 4.7 only`);
  const credsInDefaults = /defaults\s*:\s*{[^}]*\b(password|token|secret|apiKey)\b/is.test(htmlSrc);
  credsInDefaults &&
    warn("SECRET", `${basename(html)}: possible secret in defaults; inspect credentials/export behavior`);
}

// ---- examples (scorecard N02) -----------------------------------------------
const exDir = join(dir, "examples");
if (!existsSync(exDir)) warn("N02", "no examples/ folder (scorecard expects one flow per node)");
else {
  const files = readdirSync(exDir).filter((f) => f.endsWith(".json"));
  files.length || warn("N02", "examples/ has no .json flows");
  const covered = new Set();
  for (const f of files) {
    let flow;
    try {
      flow = JSON.parse(readFileSync(join(exDir, f), "utf8"));
    } catch (e) {
      fail("N02", `examples/${f}: invalid JSON (${e.message})`);
      continue;
    }
    Array.isArray(flow) || fail("N02", `examples/${f}: must be a flow array`);
    for (const n of Array.isArray(flow) ? flow : []) {
      if (registered.has(n.type)) covered.add(n.type);
      for (const k of ["password", "token", "secret", "apiKey"])
        if (typeof n[k] === "string" && n[k]) fail("SECRET", `examples/${f}: node ${n.id} carries ${k}`);
    }
  }
  for (const t of registered)
    covered.has(t) ? pass("N02", `${t}: demonstrated in an example`) : warn("N02", `${t}: no example flow uses it`);
}

// ---- tarball contents -------------------------------------------------------
try {
  const raw = execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: dir,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  const parsed = JSON.parse(raw);
  const entry = Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0]; // npm 12 returns an object keyed by name
  if (!entry || !Array.isArray(entry.files) || !entry.files.length)
    throw new Error("empty or unrecognized npm pack manifest");
  const names = entry.files.map((f) => f.path);
  for (const rel of Object.values(nodes))
    for (const file of [rel, rel.replace(/\.js$/, ".html")]) {
      if (!names.includes(file)) fail("PACK", `${file} exists in the workspace but is not packed`);
    }
  const bad = names.filter(
    (p) =>
      /^(test|tests|__tests__|coverage|docs\/superpowers|\.claude|\.codex|\.github|playwright-report|test-results)\//.test(
        p,
      ) ||
      /\.(pem|key|p12|pfx|env|log|tgz)$/.test(p) ||
      /^\.env|AGENTS\.md|CLAUDE\.md|REVIEW.*\.md/.test(p),
  );
  bad.length
    ? fail(
        "PACK",
        `tarball includes: ${bad.slice(0, 8).join(", ")}${bad.length > 8 ? " …" : ""} (add a files allowlist)`,
      )
    : pass("PACK", `${names.length} files, ${entry?.size ?? "?"} bytes`);
  pkg.files ? pass("PACK", "files allowlist present") : warn("PACK", "no files allowlist in package.json");
} catch (e) {
  fail("PACK", `npm pack --dry-run failed: ${String(e.message).split("\n")[0]}`);
}

// ---- report -----------------------------------------------------------------
for (const l of out.pass) console.log(`PASS ${l}`);
for (const l of out.warn) console.log(`WARN ${l}`);
for (const l of out.fail) console.log(`FAIL ${l}`);
console.log(`\n${out.pass.length} pass, ${out.warn.length} warn, ${out.fail.length} fail`);
process.exit(out.fail.length ? 1 : 0);
