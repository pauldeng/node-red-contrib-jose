"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { once } = require("node:events");
const jose = require("jose");
const { loadMaterial, keyFor, REMOTE_DEFAULTS } = require("../../lib/keys");
const { pairs, jwk } = require("../helpers/keys");

const load = (config) => loadMaterial({ source: "remote-jwks", algorithms: "ES256", ...config });
const unusable = (re) => ({ code: "KEY_UNUSABLE", message: re });

test("remote-jwks: URL policy, settings and defaults", () => {
  const ok = load({ url: "https://issuer.example/.well-known/jwks.json" });
  assert.equal(ok.ok, true, ok.error?.message);
  assert.deepEqual([ok.alg, ok.algorithms, ok.warning], ["ES256", ["ES256"], undefined]);
  assert.equal(typeof keyFor(ok, "verify"), "function");
  assert.throws(() => keyFor(ok, "sign"), unusable(/can only verify/));
  for (const host of ["127.0.0.1", "[::1]", "localhost"]) {
    const local = load({ url: `http://${host}:1880/jwks`, allowInsecureLoopback: true });
    assert.equal(local.ok, true, host);
    assert.match(local.warning, /plain http on loopback/);
  }
  assert.deepEqual(REMOTE_DEFAULTS, { cacheSeconds: 600, timeoutSeconds: 5 });
  assert.equal(load({ url: "https://a.example/j", cacheSeconds: "3600", timeoutSeconds: 30 }).ok, true);
  for (const [config, re] of [
    [{ url: "http://issuer.example/jwks" }, /must use https/],
    [{ url: "http://issuer.example/jwks", allowInsecureLoopback: true }, /must use https/],
    [{ url: "http://127.0.0.1/jwks" }, /must use https/],
    [{ url: "http://127.0.0.1/jwks", allowInsecureLoopback: "true" }, /must be true or false/],
    [{ url: "ftp://issuer.example/jwks" }, /must use https/],
    [{ url: "https://user:pw@issuer.example/jwks" }, /must not contain credentials/],
    [{ url: "https://issuer.example/jwks#frag" }, /must not contain a fragment/],
    [{ url: "not a url" }, /not a valid URL/],
    [{ url: "" }, /URL is empty/],
    [{}, /URL is empty/],
    [{ url: "https://a.example/j", cacheSeconds: 0 }, /cacheSeconds/],
    [{ url: "https://a.example/j", cacheSeconds: 3601 }, /cacheSeconds/],
    [{ url: "https://a.example/j", timeoutSeconds: 31 }, /timeoutSeconds/],
    [{ url: "https://a.example/j", timeoutSeconds: null }, /timeoutSeconds/],
    [{ url: "https://a.example/j", algorithms: "" }, /needs an explicit algorithm list/],
    [{ url: "https://a.example/j", algorithms: "HS256" }, /asymmetric JWS algorithms/],
    [{ url: "https://a.example/j", family: "encryption" }, /can only verify signatures/],
  ]) {
    const state = load(config);
    assert.equal(state.ok, false, JSON.stringify(config));
    assert.match(state.error.message, re);
    assert.doesNotMatch(state.error.message, /issuer\.example|user:pw/, "URL text is not echoed");
  }
});

test("remote-jwks: resolver maps every failure shape to a stable code", async (t) => {
  const pub = await jwk.public("p256", { kid: "e1", alg: "ES256" });
  const mint = (kid) =>
    new jose.SignJWT({ sub: "r" })
      .setProtectedHeader({ alg: "ES256", typ: "JWT", kid })
      .setExpirationTime("1h")
      .sign(pairs.p256.privateKey);
  const token = await mint("e1");
  const servers = {};
  const serve = async (name, handler) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    servers[name] = server;
    return `http://127.0.0.1:${server.address().port}/jwks`;
  };
  t.after(() => {
    for (const s of Object.values(servers)) (s.closeAllConnections?.(), s.close());
  });
  const json = (body) => (req, res) => {
    res.setHeader("content-type", "application/json");
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const urls = {
    ok: await serve("ok", json({ keys: [pub] })),
    s503: await serve("s503", (req, res) => {
      res.statusCode = 503;
      res.end("down");
    }),
    html: await serve("html", json("<html>")),
    redirect: await serve("redirect", (req, res) => {
      res.statusCode = 302;
      res.setHeader("location", "http://127.0.0.1:9/");
      res.end();
    }),
    malformed: await serve("malformed", json({ keys: "nope" })),
    badMember: await serve(
      "badMember",
      json({ keys: [{ kty: "EC", crv: "P-256", x: "AAAA", y: "BBBB", kid: "e1", alg: "ES256" }] }),
    ),
    stall: await serve("stall", () => {}),
    bodyStall: await serve("bodyStall", (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.write('{"keys":');
    }),
    closed: await serve("closed", () => {}),
  };
  const closed = once(servers.closed, "close");
  servers.closed.close();
  await closed;
  const verify = async (name, tok = token) => {
    const state = load({ url: urls[name], allowInsecureLoopback: true, timeoutSeconds: 1 });
    assert.equal(state.ok, true, state.error?.message);
    return jose.jwtVerify(tok, keyFor(state, "verify"), { algorithms: state.algorithms });
  };
  assert.equal((await verify("ok")).payload.sub, "r");
  for (const [name, code] of [
    ["s503", "JWKS_FETCH"],
    ["html", "JWKS_FETCH"],
    ["redirect", "JWKS_FETCH"],
    ["closed", "JWKS_FETCH"],
    ["malformed", "ERR_JWKS_INVALID"],
    ["badMember", "ERR_JWKS_INVALID"],
    ["stall", "ERR_JWKS_TIMEOUT"],
    ["bodyStall", "JWKS_FETCH"],
  ])
    await assert.rejects(verify(name), { code }, name);
  await assert.rejects(verify("ok", await mint("unknown")), { code: "ERR_JWKS_NO_MATCHING_KEY" });
});

test("remote-jwks: explicit loopback option must be boolean even for HTTPS", () => {
  for (const allowInsecureLoopback of [null, "true", "false", 0, 1, [], {}]) {
    assert.equal(load({ url: "https://issuer.example/jwks", allowInsecureLoopback }).ok, false);
  }
});

test("remote-jwks: algorithm declarations and malformed usages respect policy", async (t) => {
  let body;
  let requests = 0;
  const server = http.createServer((req, res) => {
    requests++;
    res.end(JSON.stringify(body));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const url = `http://127.0.0.1:${server.address().port}/jwks`;
  const pub = await jwk.public("rsa", { kid: "r1" });
  const token = await new jose.SignJWT({ sub: "policy" })
    .setProtectedHeader({ alg: "RS256", kid: "r1" })
    .sign(pairs.rsa.privateKey);
  const state = (algorithms) => load({ url, allowInsecureLoopback: true, algorithms });
  const verify = (s) => jose.jwtVerify(token, keyFor(s, "verify"), { algorithms: s.algorithms });
  body = { keys: [pub] };
  assert.equal((await verify(state("RS256"))).payload.sub, "policy", "one algorithm allows omitted alg");
  await assert.rejects(verify(state("RS256, PS256")), { code: "ERR_JWKS_NO_MATCHING_KEY" });
  body = { keys: [{ ...pub, alg: "RS256", key_ops: ["sign", "verify"] }] };
  await assert.rejects(verify(state("RS256")), { code: "ERR_JWKS_INVALID" });
  body = { keys: [pub, { ...pub, alg: "RS256" }] };
  const valid = state("RS256, PS256");
  const before = requests;
  await verify(valid);
  await verify(valid);
  assert.equal(requests - before, 1, "filtered sets still use jose's cache");
  for (const malformed of [{ keys: [null] }, { keys: "wrong" }, null]) {
    body = malformed;
    await assert.rejects(verify(state("RS256, PS256")), { code: "ERR_JWKS_INVALID" });
  }
});

test("remote-jwks: concurrent consumers share fetch/cache/cooldown and refresh after expiry", async (t) => {
  let requests = 0;
  let body = { keys: [await jwk.public("p256", { alg: "ES256", kid: "e1" })] };
  const server = http.createServer((req, res) => {
    requests++;
    res.end(JSON.stringify(body));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const s = load({
    url: `http://127.0.0.1:${server.address().port}/jwks`,
    allowInsecureLoopback: true,
    cacheSeconds: 60,
    algorithms: "ES256, RS256",
  });
  const mint = (kid, pair) => new jose.SignJWT({}).setProtectedHeader({ alg: "ES256", kid }).sign(pair.privateKey);
  const token = await mint("e1", pairs.p256);
  const verify = (tok = token) => jose.jwtVerify(tok, keyFor(s, "verify"), { algorithms: s.algorithms });
  await Promise.all(Array.from({ length: 10 }, () => verify()));
  assert.equal(requests, 1, "one shared fetch");
  await assert.rejects(verify(await mint("unknown", pairs.p256)), { code: "ERR_JWKS_NO_MATCHING_KEY" });
  assert.equal(requests, 1, "unknown kid respects cooldown");
  const next = require("node:crypto").generateKeyPairSync("ec", { namedCurve: "P-256" });
  body = { keys: [{ ...next.publicKey.export({ format: "jwk" }), alg: "ES256", kid: "e1" }] };
  const later = Date.now() + 61000;
  t.mock.method(Date, "now", () => later);
  await assert.rejects(verify(), { code: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" });
  await verify(await mint("e1", next));
  assert.equal(requests, 2, "one refresh replaces same-kid cached material");
});
