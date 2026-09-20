"use strict";
// Package and repository gates: what ships, what installs, and what the repo promises.
// Handles npm 12's `npm pack --json` shape (object keyed by name) and older npm (array).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..");
const pkg = require(path.join(ROOT, "package.json"));
const ALLOWED = /^(package\.json|README\.md|CHANGELOG\.md|LICENSE)$|^(nodes|lib|icons|examples)\//;

function pack(args) {
  const out = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--ignore-scripts", ...args], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }),
  );
  return Array.isArray(out) ? out[0] : Object.values(out)[0];
}

test("tarball ships only allowed paths and every declared node file", () => {
  const files = pack(["--dry-run"]).files.map((f) => f.path);
  assert.deepEqual(
    files.filter((f) => !ALLOWED.test(f)),
    [],
    "unexpected files in the tarball; fix the files allowlist",
  );
  for (const js of Object.values(pkg["node-red"].nodes))
    for (const f of [js, js.replace(/\.js$/, ".html")]) assert.ok(files.includes(f), `${f} not packed`);
});

test("packed tarball extracts and each entry registers its editor types", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pack-"));
  try {
    const { filename } = pack(["--pack-destination", tmp]);
    const dir = path.join(tmp, "node_modules", pkg.name);
    fs.mkdirSync(dir, { recursive: true });
    execFileSync("tar", ["-xzf", path.join(tmp, filename), "-C", dir, "--strip-components=1"]);
    for (const dep of Object.keys(pkg.dependencies ?? {})) {
      // offline: link the workspace copies of runtime deps
      const link = path.join(tmp, "node_modules", dep);
      fs.mkdirSync(path.dirname(link), { recursive: true });
      fs.symlinkSync(path.join(ROOT, "node_modules", dep), link, "dir");
    }
    for (const js of Object.values(pkg["node-red"].nodes)) {
      const seen = [];
      const noop = new Proxy({}, { get: () => () => {} }); // any RED.util.* / RED.x.* the module touches at load time
      require(path.join(dir, js))({
        nodes: { registerType: (t) => seen.push(t), createNode() {}, getNode() {} },
        util: noop,
        settings: noop,
        log: noop,
        events: noop,
        httpAdmin: noop,
        auth: noop,
      });
      const html = fs.readFileSync(path.join(dir, js.replace(/\.js$/, ".html")), "utf8");
      const expected = [...html.matchAll(/RED\.nodes\.registerType\(\s*["']([^"']+)["']/g)].map((m) => m[1]);
      assert.ok(expected.length, "editor registration smoke test requires static type names");
      assert.deepEqual(seen.sort(), expected.sort(), `${js} runtime/editor types differ`);
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("package metadata promises hold", () => {
  assert.ok(pkg.keywords?.includes("node-red"));
  assert.equal(pkg.publishConfig?.access, "public");
  assert.ok(pkg["node-red"]?.version, "declare supported Node-RED versions");
  const lockPath = path.join(ROOT, "package-lock.json");
  assert.ok(fs.existsSync(lockPath), "npm ci requires a committed lockfile");
  const lock = require(lockPath).packages[""];
  for (const k of ["name", "version", "license"]) assert.equal(lock[k], pkg[k], `lockfile ${k} stale; run npm install`);
  assert.deepEqual(lock.engines, pkg.engines, "lockfile engines stale");
  assert.deepEqual(lock.dependencies, pkg.dependencies, "lockfile runtime dependencies stale");
  assert.deepEqual(lock.devDependencies, pkg.devDependencies, "lockfile development dependencies stale");
});

test("CI matrix tests the declared Node floor without requiring a release workflow", () => {
  const ci = fs.readFileSync(path.join(ROOT, ".github/workflows/ci.yml"), "utf8").replace(/(^|\s)#.*$/gm, "");
  const floor = pkg.engines.node.match(/^>=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?$/);
  assert.ok(floor, "update the CI contract when changing the supported engine range");
  const [, major, minor = "0", patch = "0"] = floor;
  const matrix = ci.match(/matrix:\s*\{\s*node:\s*\[([^\]]+)\]/);
  assert.ok(matrix, "expected the explicit inline Node matrix; update this check if CI structure changes");
  const versions = [...matrix[1].matchAll(/["']([^"']+)["']/g)].map((m) => m[1]);
  assert.ok(
    versions.includes(`${major}.${minor}.${patch}`) || (patch === "0" && versions.includes(`${major}.${minor}`)),
    `ci.yml must exercise floor ${major}.${minor}.${patch}; a floating major does not test the floor`,
  );
});

test("release requires an explicit version tag, public repository and token-free OIDC", () => {
  const rel = path.join(ROOT, ".github/workflows/release.yml");
  assert.ok(fs.existsSync(rel), "release workflow is required before publication");
  const release = fs.readFileSync(rel, "utf8").replace(/(^|\s)#.*$/gm, ""); // drop full-line and inline comments
  assert.doesNotMatch(release, /NPM_TOKEN|NODE_AUTH_TOKEN|npm login|secrets\./, "release must not use tokens");
  assert.match(release, /workflow_dispatch:/);
  assert.doesNotMatch(release, /^\s+(push|pull_request|release):/m, "publication requires a manual dispatch");
  assert.match(release, /environment: release/);
  assert.match(release, /id-token: write/);
  assert.match(release, /package-manager-cache: false/);
  assert.match(release, /--provenance/);
  for (const gate of ["npm test", "npm run check:release", "npm audit --omit=dev", "npm run check:install"])
    assert.ok(release.indexOf(gate) >= 0 && release.indexOf(gate) < release.indexOf("npm publish --provenance"));

  // Execute the actual shell guard: branch dispatches and wrong tags must fail, including shell-like input.
  const guard = release.match(/run: \|\n((?: {10}[^\n]*\n)+)/)?.[1];
  assert.ok(guard, "release must retain an executable pre-publication guard");
  const runGuard = (ref, isPrivate = "false") =>
    execFileSync("sh", ["-e", "-c", guard], {
      cwd: ROOT,
      env: { ...process.env, RELEASE_REF: ref, REPOSITORY_PRIVATE: isPrivate },
      stdio: "pipe",
    });
  assert.doesNotThrow(() => runGuard(`refs/tags/v${pkg.version}`));
  for (const ref of ["refs/heads/main", "refs/tags/v999.0.0", "refs/tags/v$(exit 0)", ""])
    assert.throws(() => runGuard(ref));
  assert.throws(() => runGuard(`refs/tags/v${pkg.version}`, "true"));
});

test("the main branch ruleset requires exactly the CI jobs", () => {
  const ci = fs.readFileSync(path.join(ROOT, ".github/workflows/ci.yml"), "utf8").replace(/(^|\s)#.*$/gm, "");
  const versions = [...ci.match(/matrix:\s*\{\s*node:\s*\[([^\]]+)\]/)[1].matchAll(/["']([^"']+)["']/g)].map(
    (m) => m[1],
  );
  const expected = [...ci.matchAll(/^ {4}name: (.+)$/gm)].flatMap(([, name]) =>
    name.includes("${{ matrix.node }}") ? versions.map((v) => name.replace("${{ matrix.node }}", v)) : [name],
  );
  const ruleset = JSON.parse(fs.readFileSync(path.join(ROOT, ".github/rulesets/main.json"), "utf8"));
  assert.deepEqual(ruleset.bypass_actors, [], "nobody bypasses main protection");
  const checks = ruleset.rules.find((r) => r.type === "required_status_checks").parameters.required_status_checks;
  assert.deepEqual(checks.map((c) => c.context).sort(), expected.sort(), "ruleset checks must match CI job names");
  assert.ok(
    ruleset.rules.some((r) => r.type === "pull_request"),
    "main accepts pull requests only",
  );
});
