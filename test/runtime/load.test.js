"use strict";
// M0: the package loads inside a real Node-RED (so require("jose") works there) and password credentials round-trip.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { once } = require("node:events");
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

test("test admin API rejects anonymous and incorrect-token clients", async (t) => {
  const nr = await startNodeRed({ packageDir: PKG });
  t.after(() => nr.stop());
  for (const headers of [{}, { authorization: "Bearer incorrect" }]) {
    for (const method of ["GET", "POST"]) {
      const res = await fetch(nr.base + "/flows", {
        method,
        headers: { "content-type": "application/json", ...headers },
        ...(method === "POST" ? { body: "[]" } : {}),
        signal: AbortSignal.timeout(5000),
      });
      assert.equal(res.status, 401, `${method} /flows requires the per-run admin token`);
      await res.text();
    }
  }
  assert.ok(Array.isArray(await nr.api("GET", "/flows")), "authenticated client still works");
});

test("test comms rejects unauthenticated and wrong-token subscriptions", async (t) => {
  const nr = await startNodeRed({ packageDir: PKG });
  t.after(() => nr.stop());
  for (const packet of [{ subscribe: "debug" }, { auth: "incorrect" }]) {
    const ws = new WebSocket(`ws://127.0.0.1:${nr.port}/comms`);
    try {
      await once(ws, "open", { signal: AbortSignal.timeout(5000) });
      const response = once(ws, "message", { signal: AbortSignal.timeout(5000) });
      ws.send(JSON.stringify(packet));
      const [event] = await response;
      assert.deepEqual(JSON.parse(event.data), { auth: "fail" });
    } finally {
      ws.close();
    }
  }
});
