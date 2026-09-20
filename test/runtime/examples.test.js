"use strict";
// Every example deploys in a real Node-RED with test credentials injected and produces its documented output.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { startNodeRed } = require("../helpers/node-red");
const { pem, jwk } = require("../helpers/keys");

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

// Default run: press one inject and check one debug output. prepare() adapts a flow to the harness before deploy.
async function injectAndCheck(nr, flow, { inject, debug, check }) {
  const debugNode = flow.find((n) => n.id === debug);
  const [d] = await Promise.all([nr.waitForDebug((m) => m.id === debug), nr.inject(inject)]);
  check(debugNode.complete === "true" ? d.msg : { payload: d.msg });
}

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
  "03-rs256-pem-key.json": {
    inject: "jose_ex3_inject",
    debug: "jose_ex3_claims",
    check: (msg) => {
      assert.equal(msg.payload.sub, "alice");
      assert.equal(msg.payload.iss, "https://issuer.example");
      assert.equal(msg.payload.aud, "example-api");
      assert.match(msg.payload.jti, /^[0-9a-f-]{36}$/);
      assert.deepEqual(msg.header, { alg: "RS256", typ: "JWT", kid: "demo-2026" });
    },
  },
  "04-verify-with-remote-jwks.json": {
    // The user pastes a private JWK and the matching public set; the test generates both and points the URL at the harness.
    prepare: async (flow, nr) => {
      const priv = await jwk.private("p256", { kid: "example-2026", alg: "ES256", use: "sig" });
      const pub = { ...priv };
      delete pub.d;
      flow.find((n) => n.id === "jose_ex4_signkey").credentials = { jwk: JSON.stringify(priv) };
      flow.find((n) => n.id === "jose_ex4_template").template = JSON.stringify({ keys: [pub] });
      flow.find((n) => n.id === "jose_ex4_jwkskey").url = `http://127.0.0.1:${nr.port}/jose-example-jwks`;
    },
    inject: "jose_ex4_inject",
    debug: "jose_ex4_claims",
    check: (msg) => {
      assert.equal(msg.payload.sub, "alice");
      assert.deepEqual(msg.header, { alg: "ES256", typ: "JWT", kid: "example-2026" });
    },
  },
  "05-http-bearer-auth.json": {
    run: async (nr, flow) => {
      const [d] = await Promise.all([nr.waitForDebug((m) => m.id === "jose_ex5_token"), nr.inject("jose_ex5_inject")]);
      const token = d.msg;
      const url = `${nr.base}/jose-example-protected`;
      const ok = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
      assert.equal(ok.status, 200);
      const claims = await ok.json();
      assert.equal(claims.sub, "alice");
      assert.equal(claims.iss, "https://issuer.example");
      for (const headers of [{}, { authorization: `Bearer ${token.slice(0, -2)}xx` }, { authorization: "Basic abc" }]) {
        const denied = await fetch(url, { headers });
        assert.equal(denied.status, 401, JSON.stringify(headers));
        assert.deepEqual(await denied.json(), { error: "invalid_token" });
      }
      flow.find((n) => n.id === "jose_ex5_key").credentials = { secret: "" };
      await nr.deploy(flow, "nodes");
      const unavailable = await fetch(url, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(1500),
      });
      assert.equal(unavailable.status, 503, "configuration faults must also complete the HTTP request");
      assert.deepEqual(await unavailable.json(), { error: "service_unavailable" });
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
      if (n.type === "jose-key" && n.source !== "remote-jwks" && n.source !== "jwk")
        n.credentials =
          n.source === "pem" ? { pem: pem.pkcs8("rsa") } : { secret: crypto.randomBytes(32).toString("base64") };
    const scenario = SCENARIOS[f];
    if (scenario.prepare) await scenario.prepare(flow, nr);
    await nr.deploy(flow);
    if (scenario.run) await scenario.run(nr, flow);
    else await injectAndCheck(nr, flow, scenario);
  });
