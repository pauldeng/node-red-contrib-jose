// Pack the package, install the tarball into a fresh Node-RED 5 inside node:24-alpine, and round-trip example 01.
// This is the "clean install" release evidence: no workspace node_modules, no nodesDir, the real npm install path.
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, copyFileSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const nodeRedVersion = pkg.devDependencies["node-red"];
const dir = mkdtempSync(join(tmpdir(), "jose-clean-install-"));
const containerName = `jose-clean-install-${process.pid}-${Date.now()}`;
const expectedTypes = Object.keys(pkg["node-red"].nodes).sort().join();

const check = `"use strict";
const crypto = require("node:crypto");
const { startNodeRed } = require("./node-red.js");
(async () => {
  // The package is loaded from node_modules like any installed node; nodesDir is emptied on purpose.
  const nr = await startNodeRed({ packageDir: process.cwd(), settings: { nodesDir: [] }, timeoutMs: 90_000 });
  try {
    const sets = await nr.api("GET", "/nodes", undefined, { accept: "application/json" });
    const mine = sets.filter((s) => s.module === ${JSON.stringify(pkg.name)});
    const types = mine.flatMap((s) => s.types).sort();
    if (!mine.length || mine.some((s) => !s.enabled || s.err)) throw new Error("node set not loaded: " + JSON.stringify(mine));
    if (types.join() !== ${JSON.stringify(expectedTypes)}) throw new Error("types differ: " + types.join());
    const flow = require(${JSON.stringify(pkg.name + "/examples/01-sign-and-verify-hs256.json")});
    for (const n of flow) if (n.type === "jose-key") n.credentials = { secret: crypto.randomBytes(32).toString("base64") };
    await nr.deploy(flow);
    const [d] = await Promise.all([nr.waitForDebug((m) => m.id === "jose_ex1_claims"), nr.inject("jose_ex1_inject")]);
    if (d.msg.sub !== "alice") throw new Error("example 01 did not round-trip: " + JSON.stringify(d.msg));
    console.log("CLEAN INSTALL OK: " + ${JSON.stringify(`${pkg.name}@${pkg.version}`)} + " loaded " + types.join(", ") + " and example 01 round-tripped");
  } finally {
    await nr.stop();
  }
})().catch((err) => {
  console.error("CLEAN INSTALL FAILED:", err.message);
  process.exit(1);
});
`;

try {
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", dir], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }),
  );
  const tgz = (Array.isArray(packed) ? packed[0] : Object.values(packed)[0]).filename;
  copyFileSync(join(ROOT, "test/helpers/node-red.js"), join(dir, "node-red.js"));
  writeFileSync(join(dir, "check.cjs"), check);
  const script = [
    "set -e",
    "npm init -y >/dev/null",
    `npm install --no-audit --no-fund --loglevel=error node-red@${nodeRedVersion} ./${tgz}`,
    "node --version",
    `node -e 'console.log("installed:", require("${pkg.name}/package.json").version, "node-red:", require("node-red/package.json").version)'`,
    "node check.cjs",
  ].join("\n");
  // Run as the invoking user so the container never leaves root-owned files behind.
  const asUser = process.getuid
    ? ["--user", `${process.getuid()}:${process.getgid()}`, "-e", "HOME=/w", "-e", "npm_config_cache=/w/.npm"]
    : [];
  const run = spawnSync(
    "docker",
    [
      "run",
      "--rm",
      "--name",
      containerName,
      ...asUser,
      "-v",
      `${dir}:/w`,
      "-w",
      "/w",
      "node:24-alpine",
      "sh",
      "-c",
      script,
    ],
    {
      stdio: "inherit",
      timeout: 600_000,
    },
  );
  if (run.status !== 0) {
    throw new Error(`clean install failed (${run.error?.code ?? `exit ${run.status}`})`);
  }
} finally {
  // A killed/timed-out docker client may leave its container running. Remove it before deleting the mount.
  spawnSync("docker", ["rm", "-f", "-v", containerName], { stdio: "ignore", timeout: 10_000 });
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch (err) {
    console.warn(`temporary directory ${dir} could not be removed: ${err.code}`); // cleanup is best effort
  }
}
