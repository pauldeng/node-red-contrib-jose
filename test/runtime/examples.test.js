"use strict";
// Every example deploys in a real Node-RED with a test credential injected and produces its documented output.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { startNodeRed } = require("../helpers/node-red");

const PKG = path.resolve(__dirname, "../..");
const pkg = require(path.join(PKG, "package.json"));
const PACKAGE_TYPES = new Set(Object.keys(pkg["node-red"].nodes));
const CORE_TYPES = new Set([
  "tab",
  "comment",
  "inject",
  "debug",
  "catch",
  "change",
  "http in",
  "http response",
  "template",
  "switch",
]);

// One entry per example: which inject to press and what the documented output looks like.
const SCENARIOS = {
  "01-sign-and-verify-hs256.json": {
    inject: "jose_ex1_inject",
    debug: "jose_ex1_claims",
    check: (msg) => {
      assert.equal(msg.payload.sub, "alice");
      assert.equal(msg.payload.role, "admin");
      assert.equal(msg.payload.exp - msg.payload.iat, 3600);
    },
  },
  "02-encrypt-and-decrypt.json": {
    inject: "jose_ex2_inject",
    debug: "jose_ex2_claims",
    check: (msg) => {
      assert.equal(msg.payload.sub, "alice");
      assert.equal(msg.payload.aud, "example-service");
      assert.equal(msg.payload.exp - msg.payload.iat, 3600);
    },
  },
};

const files = fs.readdirSync(path.join(PKG, "examples")).filter((f) => f.endsWith(".json"));

test("every example has a scenario and uses only package or core node types", () => {
  assert.deepEqual(files.sort(), Object.keys(SCENARIOS).sort());
  for (const f of files) {
    const flow = JSON.parse(fs.readFileSync(path.join(PKG, "examples", f), "utf8"));
    for (const n of flow)
      assert.ok(PACKAGE_TYPES.has(n.type) || CORE_TYPES.has(n.type), `${f}: node ${n.id} type ${n.type}`);
    for (const n of flow) assert.equal(n.credentials, undefined, `${f}: node ${n.id} carries credentials`);
  }
});

for (const f of files)
  test(`example ${f} round-trips`, async (t) => {
    const nr = await startNodeRed({ packageDir: PKG });
    t.after(() => nr.stop());
    const flow = JSON.parse(fs.readFileSync(path.join(PKG, "examples", f), "utf8"));
    for (const n of flow)
      if (n.type === "jose-key") n.credentials = { secret: crypto.randomBytes(32).toString("base64") };
    await nr.deploy(flow);
    const { inject, debug, check } = SCENARIOS[f];
    const [msg] = await Promise.all([nr.waitForDebug((d) => d.id === debug), nr.inject(inject)]);
    check(msg.msg !== undefined && msg.format === undefined ? msg : { payload: msg.msg });
  });
