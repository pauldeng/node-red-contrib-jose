"use strict";
// M4: remote JSON Web Key Sets in real flows: loopback http with opt-in, https with a throwaway certificate,
// kid selection, and every failure shape mapped to its code and route.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const http = require("node:http");
const https = require("node:https");
const { once } = require("node:events");
const { spawnSync } = require("node:child_process");
const jose = require("jose");
const { startNodeRed } = require("../helpers/node-red");
const { pairs, jwk } = require("../helpers/keys");

const PKG = path.resolve(__dirname, "../..");
let nr;
let seq = 0;
const servers = [];
const urls = {};
let tls; // throwaway certificate; openssl is a required runtime-test prerequisite

async function serve(name, handler, secure) {
  const server = secure ? https.createServer(secure, handler) : http.createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  servers.push(server);
  urls[name] = `${secure ? "https" : "http"}://127.0.0.1:${server.address().port}/jwks`;
}

test.before(async () => {
  const pub = await jwk.public("p256", { kid: "e1", alg: "ES256" });
  const jwks = (req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ keys: [pub] }));
  };
  await serve("ok", jwks);
  await serve("s503", (req, res) => {
    res.statusCode = 503;
    res.end("down");
  });
  await serve("stall", () => {});
  await serve("bodyStall", (req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.write('{"keys":');
  });
  await serve("closed", () => {});
  const closed = once(servers.at(-1), "close");
  servers.at(-1).close();
  await closed;
  // A self-signed certificate for 127.0.0.1 makes the https path real; the child trusts it through NODE_EXTRA_CA_CERTS.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "jose-tls-"));
  tls = { dir };
  const made = spawnSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-keyout",
      "key.pem",
      "-out",
      "cert.pem",
      "-days",
      "2",
      "-subj",
      "/CN=127.0.0.1",
      "-addext",
      "subjectAltName=IP:127.0.0.1",
    ],
    { cwd: dir, stdio: "ignore" },
  );
  assert.equal(made.status, 0, "openssl must be installed and able to mint the TLS test certificate");
  {
    const previous = process.env.NODE_EXTRA_CA_CERTS;
    process.env.NODE_EXTRA_CA_CERTS = path.join(dir, "cert.pem");
    await serve("tls", jwks, {
      key: fs.readFileSync(path.join(dir, "key.pem")),
      cert: fs.readFileSync(path.join(dir, "cert.pem")),
    });
    try {
      nr = await startNodeRed({
        packageDir: PKG,
        settings: { logging: { console: { level: "debug", metrics: false, audit: false } } },
      });
    } finally {
      if (previous === undefined) delete process.env.NODE_EXTRA_CA_CERTS;
      else process.env.NODE_EXTRA_CA_CERTS = previous;
    }
  }
});
test.after(async () => {
  await nr?.stop();
  for (const s of servers) {
    s.closeAllConnections();
    s.close();
  }
  if (tls) fs.rmSync(tls.dir, { recursive: true, force: true });
});

const ids = () => {
  const n = ++seq;
  return new Proxy({}, { get: (_, k) => `${k}_${n}` });
};
const mint = (kid) =>
  new jose.SignJWT({ sub: "remote" })
    .setProtectedHeader({ alg: "ES256", typ: "JWT", kid })
    .setExpirationTime("1h")
    .sign(pairs.p256.privateKey);
const flow = (id, token, key, verifyExtra = {}) => [
  { id: id.tab, type: "tab", label: id.tab },
  {
    id: id.key,
    type: "jose-key",
    name: "remote",
    family: "signing",
    source: "remote-jwks",
    algorithms: "ES256",
    cacheSeconds: 60,
    timeoutSeconds: 1,
    ...key,
  },
  {
    id: id.inject,
    type: "inject",
    z: id.tab,
    props: [{ p: "payload" }],
    payload: token,
    payloadType: "str",
    wires: [[id.verify]],
  },
  {
    id: id.verify,
    type: "jose-verify",
    z: id.tab,
    key: id.key,
    tokenFrom: "payload",
    tokenFromType: "msg",
    stripBearer: false,
    claimsTo: "payload",
    claimsToType: "msg",
    failureMode: "output",
    ...verifyExtra,
    wires: [[id.claims], [id.rejected]],
  },
  {
    id: id.claims,
    type: "debug",
    z: id.tab,
    active: true,
    tosidebar: true,
    complete: "true",
    targetType: "msg",
    wires: [],
  },
  {
    id: id.rejected,
    type: "debug",
    z: id.tab,
    active: true,
    tosidebar: true,
    complete: "true",
    targetType: "msg",
    wires: [],
  },
  { id: id.catch, type: "catch", z: id.tab, scope: null, uncaught: false, wires: [[id.caught]] },
  {
    id: id.caught,
    type: "debug",
    z: id.tab,
    active: true,
    tosidebar: true,
    complete: "true",
    targetType: "msg",
    wires: [],
  },
];
async function run(id, nodes, debugId) {
  await nr.deploy(nodes);
  const [d] = await Promise.all([nr.waitForDebug((m) => m.id === debugId), nr.inject(id.inject)]);
  return d.msg;
}

test("loopback http with the opt-in verifies by kid and warns exactly once at deploy", async () => {
  const id = ids();
  const before = nr.lines.filter((l) => /plain http on loopback/.test(l)).length;
  const msg = await run(id, flow(id, await mint("e1"), { url: urls.ok, allowInsecureLoopback: true }), id.claims);
  assert.equal(msg.payload.sub, "remote");
  assert.equal(
    nr.lines.filter((l) => /\[warn\] \[jose-key:remote\] .*plain http on loopback/.test(l)).length,
    before + 1,
  );
});

test("an unknown kid is a token rejection on the chosen route", async () => {
  const id = ids();
  const msg = await run(id, flow(id, await mint("nope"), { url: urls.ok, allowInsecureLoopback: true }), id.rejected);
  assert.equal(msg.error.code, "ERR_JWKS_NO_MATCHING_KEY");
});

test("503, closed port and a stalled endpoint are operational faults that always throw", async () => {
  for (const [name, code] of [
    ["s503", "JWKS_FETCH"],
    ["closed", "JWKS_FETCH"],
    ["stall", "ERR_JWKS_TIMEOUT"],
    ["bodyStall", "JWKS_FETCH"],
  ]) {
    const id = ids();
    const msg = await run(id, flow(id, await mint("e1"), { url: urls[name], allowInsecureLoopback: true }), id.caught);
    assert.equal(msg.error.code, code, name);
    assert.equal(msg.error.cause, undefined);
    assert.doesNotMatch(msg.error.message, /127\.0\.0\.1/, "no URL in the error");
  }
});

test("plain http without the opt-in is KEY_UNUSABLE at deploy", async () => {
  const id = ids();
  const status = nr.waitForStatus(id.verify, (s) => s.text === "key error");
  await nr.deploy(flow(id, await mint("e1"), { url: urls.ok }));
  await status;
  const [caught] = await Promise.all([nr.waitForDebug((m) => m.id === id.caught), nr.inject(id.inject)]);
  assert.equal(caught.msg.error.code, "KEY_UNUSABLE");
  assert.match(caught.msg.error.message, /must use https/);
});

test("https with a trusted certificate verifies without any opt-in", async () => {
  const id = ids();
  const msg = await run(id, flow(id, await mint("e1"), { url: urls.tls }), id.claims);
  assert.equal(msg.payload.sub, "remote");
  assert.match(urls.tls, /^https:/);
});

test("HTTPS rejects an untrusted certificate even with the loopback opt-in", async (t) => {
  const untrusted = await startNodeRed({ packageDir: PKG });
  t.after(() => untrusted.stop());
  const id = ids();
  await untrusted.deploy(flow(id, await mint("e1"), { url: urls.tls, allowInsecureLoopback: true }));
  const [caught] = await Promise.all([untrusted.waitForDebug((m) => m.id === id.caught), untrusted.inject(id.inject)]);
  assert.equal(caught.msg.error.code, "JWKS_FETCH");
  assert.equal(caught.msg.error.cause, undefined);
});

test("remote algorithm policy rejects undeclared keys and malformed keys use Catch", async () => {
  const pub = await jwk.public("p256", { kid: "e1" });
  let body = { keys: [pub] };
  await serve("policy", (req, res) => res.end(JSON.stringify(body)));
  let id = ids();
  let msg = await run(
    id,
    flow(id, await mint("e1"), { url: urls.policy, allowInsecureLoopback: true, algorithms: "ES256, RS256" }),
    id.rejected,
  );
  assert.equal(msg.error.code, "ERR_JWKS_NO_MATCHING_KEY");
  body = { keys: [{ ...pub, key_ops: ["sign", "verify"] }] };
  id = ids();
  msg = await run(id, flow(id, await mint("e1"), { url: urls.policy, allowInsecureLoopback: true }), id.caught);
  assert.equal(msg.error.code, "ERR_JWKS_INVALID");
  assert.equal(msg.error.cause, undefined);
});

for (const late of ["success", "failure"])
  test(
    `partial consumer redeploy during shared JWKS ${late} settles close and preserves its sibling`,
    { timeout: 10000 },
    async () => {
      const requested = Promise.withResolvers();
      const release = Promise.withResolvers();
      let requests = 0;
      let fail = late === "failure";
      const pub = await jwk.public("p256", { kid: "e1", alg: "ES256" });
      await serve("pending", async (req, res) => {
        requests++;
        requested.resolve();
        await release.promise;
        res.statusCode = fail ? 503 : 200;
        res.end(JSON.stringify({ keys: [pub] }));
      });
      const id = ids();
      const nodes = flow(id, await mint("e1"), { url: urls.pending, allowInsecureLoopback: true, timeoutSeconds: 5 });
      const original = nodes.find((n) => n.id === id.verify);
      nodes.push({ ...original, id: id.sibling, wires: [[id.siblingClaims], [id.rejected]] });
      nodes.push({ ...nodes.find((n) => n.id === id.claims), id: id.siblingClaims });
      nodes.find((n) => n.id === id.inject).wires[0].push(id.sibling);
      await nr.deploy(nodes);
      const caught = nr.waitForDebug((m) => m.id === id.caught && m.msg.error.source.id === id.verify);
      const sibling = nr.waitForDebug((m) =>
        fail ? m.id === id.caught && m.msg.error.source.id === id.sibling : m.id === id.siblingClaims,
      );
      try {
        await nr.inject(id.inject);
        await requested.promise;
        original.name = "restarted while waiting";
        await nr.deploy(nodes, "nodes");
        const closed = await caught;
        assert.equal(closed.msg.error.code, "NODE_CLOSING");
        release.resolve();
        const result = (await sibling).msg;
        if (fail) assert.equal(result.error.code, "JWKS_FETCH");
        else assert.equal(result.payload.sub, "remote");
        fail = false;
        const [fresh] = await Promise.all([nr.waitForDebug((m) => m.id === id.claims), nr.inject(id.inject)]);
        assert.equal(fresh.msg.payload.sub, "remote");
        assert.notEqual(fresh.msg._msgid, closed.msg._msgid, "the restarted node only sends new input");
        assert.equal(
          requests,
          late === "success" ? 1 : 2,
          "shared resolver retains cache or recovers after a failed fetch",
        );
      } finally {
        release.resolve();
      }
    },
  );
