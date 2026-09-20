"use strict";
// M0: the package loads inside a real Node-RED (so require("jose") works there) and password credentials round-trip.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { startNodeRed } = require("../helpers/node-red");
const credentials = require("../helpers/credentials");

const PKG = path.resolve(__dirname, "../..");
const pkg = require(path.join(PKG, "package.json"));
// password credentials are reported to the editor as has_<name> flags only, one per declared credential
const HAS = { has_secret: false, has_pem: true, has_passphrase: false, has_jwk: false };

test("jose-key registers, jose loads, and a multi-line password credential reaches the runtime", async (t) => {
  const nr = await startNodeRed({ packageDir: PKG, settings: credentials.settings });
  t.after(() => nr.stop());

  const sets = await nr.api("GET", "/nodes", undefined, { accept: "application/json" });
  const set = sets.find((s) => s.module === pkg.name && s.types.includes("jose-key"));
  assert.ok(set, "jose-key node set is listed");
  assert.equal(set.enabled, true);
  assert.equal(set.err, undefined, "node set loaded without error");

  await nr.deploy(credentials.flow());
  assert.deepEqual(await credentials.observe(nr), { pem: 1, jwk: 0 }, "exact multi-line value reached the runtime");

  assert.deepEqual(await nr.api("GET", "/credentials/jose-key/key1"), HAS);
  const flows = JSON.stringify(await nr.api("GET", "/flows"));
  assert.ok(!flows.includes("AAAA"), "credential text must not appear in the flow export");
  assert.doesNotMatch(nr.lines.join("\n"), /AAAA|BBBB|pem credential:|jose loaded with/);
});
