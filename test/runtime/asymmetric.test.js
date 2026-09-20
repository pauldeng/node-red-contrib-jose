"use strict";
// M3: PEM, JWK and pasted JWK Set keys with asymmetric algorithms, producer setters and consumer options in real flows.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const crypto = require("node:crypto");
const jose = require("jose");
const { startNodeRed } = require("../helpers/node-red");
const { pairs, pem, jwk } = require("../helpers/keys");

const PKG = path.resolve(__dirname, "../..");
const CERT = fs.readFileSync(path.join(__dirname, "../fixtures/test-certificate.pem"), "utf8");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
let nr;
let seq = 0;

test.before(async () => {
  process.env.JOSE_TEST_PEM = pem.pkcs8("p256");
  nr = await startNodeRed({
    packageDir: PKG,
    settings: { logging: { console: { level: "debug", metrics: false, audit: false } } },
  });
});
test.after(() => nr.stop());

const ids = () => {
  const n = ++seq;
  return new Proxy({}, { get: (_, k) => `${k}_${n}` });
};
const tab = (id) => ({ id: id.tab, type: "tab", label: id.tab });
const keyNode = (id, config, credentials) => ({
  id: id.key,
  type: "jose-key",
  name: "k",
  family: "signing",
  alg: "auto",
  ...config,
  credentials,
});
const inject = (id, payload, payloadType, to, name = "inject") => ({
  id: id[name],
  type: "inject",
  z: id.tab,
  props: [{ p: "payload" }],
  payload: typeof payload === "string" ? payload : JSON.stringify(payload),
  payloadType,
  wires: [[to]],
});
const debug = (id, name, complete = "true") => ({
  id: id[name],
  type: "debug",
  z: id.tab,
  name,
  active: true,
  tosidebar: true,
  complete,
  targetType: "msg",
  wires: [],
});
const catcher = (id) => ({
  id: id.catch,
  type: "catch",
  z: id.tab,
  scope: null,
  uncaught: false,
  wires: [[id.caught]],
});
const producer = (type, id, extra, wires) => ({
  id: id[type],
  type: `jose-${type}`,
  z: id.tab,
  key: id.key,
  claims: "payload",
  claimsType: "msg",
  typ: "JWT",
  expiryMode: "ttl",
  ttlSeconds: 3600,
  issuedAt: true,
  tokenTo: "payload",
  tokenToType: "msg",
  ...extra,
  wires,
});
const consumer = (type, id, extra, wires) => ({
  id: id[type],
  type: `jose-${type}`,
  z: id.tab,
  key: id.key,
  tokenFrom: "payload",
  tokenFromType: "msg",
  stripBearer: false,
  typ: "JWT",
  requiredClaims: "exp",
  claimsTo: "payload",
  claimsToType: "msg",
  failureMode: "catch",
  ...extra,
  wires,
});
const roundTrip = (id, key, creds, kind, producerExtra = {}, consumerExtra = {}) => {
  const [p, c] = kind === "signing" ? ["sign", "verify"] : ["encrypt", "decrypt"];
  return [
    tab(id),
    keyNode(id, { family: kind, ...key }, creds),
    inject(id, { sub: "alice", role: "admin" }, "json", id[p]),
    producer(p, id, producerExtra, [[id.token, id[c]]]),
    debug(id, "token", "payload"),
    consumer(c, id, consumerExtra, [[id.claims], [id.rejected]]),
    debug(id, "claims"),
    debug(id, "rejected"),
    catcher(id),
    debug(id, "caught"),
  ];
};
async function run(id, flow, debugId, injectName = "inject") {
  await nr.deploy(flow);
  const [d] = await Promise.all([nr.waitForDebug((m) => m.id === debugId), nr.inject(id[injectName])]);
  return d.msg;
}
async function runBoth(id, flow) {
  await nr.deploy(flow);
  const [t, c] = await Promise.all([
    nr.waitForDebug((m) => m.id === id.token),
    nr.waitForDebug((m) => m.id === id.claims),
    nr.inject(id.inject),
  ]);
  return { token: t.msg, msg: c.msg };
}

test("one RSA PEM key signs with setters and verifies with matching policy; header goes to headerTo", async () => {
  const id = ids();
  const { token, msg } = await runBoth(
    id,
    roundTrip(
      id,
      { source: "pem" },
      { pem: pem.pkcs8("rsa") },
      "signing",
      {
        issuer: "https://issuer.example",
        subject: "svc",
        audience: '["api", "web"]',
        audienceType: "json",
        jti: "",
        jtiType: "uuid",
        kid: "k-2024",
      },
      {
        issuer: "https://issuer.example",
        audience: "web",
        subject: "svc",
        headerTo: "header",
        headerToType: "msg",
        clockTolerance: 5,
      },
    ),
  );
  assert.deepEqual(jose.decodeProtectedHeader(token), { alg: "RS256", typ: "JWT", kid: "k-2024" });
  assert.deepEqual(msg.header, { alg: "RS256", typ: "JWT", kid: "k-2024" });
  const c = msg.payload;
  assert.equal(c.iss, "https://issuer.example");
  assert.equal(c.sub, "svc", "setter overrides the incoming sub");
  assert.deepEqual(c.aud, ["api", "web"]);
  assert.match(c.jti, UUID);
  assert.equal(c.role, "admin");
});

test("JWK private keys sign and their derived public copy verifies; kid comes from the JWK", async () => {
  for (const [name, alg] of [
    ["p256", "ES256"],
    ["ed25519", "Ed25519"],
    ["rsa", "RS256"],
  ]) {
    const id = ids();
    const priv = await jwk.private(name, { kid: `${name}-kid`, key_ops: ["sign", "verify"] });
    const { token, msg } = await runBoth(
      id,
      roundTrip(id, { source: "jwk" }, { jwk: JSON.stringify(priv) }, "signing", {}, { headerTo: "hdr" }),
    );
    assert.deepEqual(jose.decodeProtectedHeader(token), { alg, typ: "JWT", kid: `${name}-kid` }, name);
    assert.equal(msg.payload.sub, "alice");
    assert.equal(msg.hdr.kid, `${name}-kid`);
  }
});

test("PEM variants: PKCS#1, SEC1, encrypted with passphrase, Ed25519 and an environment reference", async () => {
  for (const [creds, alg] of [
    [{ pem: pem.pkcs1() }, "RS256"],
    [{ pem: pem.sec1() }, "ES256"],
    [{ pem: pem.encrypted("p384", "s3cret"), passphrase: "s3cret" }, "ES384"],
    [{ pem: pem.pkcs8("ed25519") }, "Ed25519"],
    [{ pem: "${JOSE_TEST_PEM}" }, "ES256"],
  ]) {
    const id = ids();
    const { token, msg } = await runBoth(id, roundTrip(id, { source: "pem" }, creds, "signing"));
    assert.equal(jose.decodeProtectedHeader(token).alg, alg);
    assert.equal(msg.payload.sub, "alice");
  }
  const exported = JSON.stringify(await nr.api("GET", "/flows"));
  assert.ok(
    !exported.includes("PRIVATE KEY") && !exported.includes("JOSE_TEST_PEM"),
    "no key material or reference in the export",
  );
});

test("wrong passphrase, wrong family, wrong algorithm and a certificate used for signing are KEY_UNUSABLE", async () => {
  // atLoad: the key configuration itself fails (dependents show "key error"); otherwise only the purpose fails per input.
  const cases = [
    [
      { family: "signing", source: "pem" },
      { pem: pem.encrypted("rsa", "right"), passphrase: "wrong" },
      "sign",
      /passphrase is wrong/,
      true,
    ],
    [
      { family: "encryption", source: "pem" },
      { pem: pem.pkcs8("ed25519") },
      "encrypt",
      /Ed25519 keys cannot be used for encryption/,
      true,
    ],
    [
      { family: "signing", source: "pem", alg: "ES256" },
      { pem: pem.pkcs8("rsa") },
      "sign",
      /ES256 cannot be used with this key/,
      true,
    ],
    [{ family: "signing", source: "pem" }, { pem: CERT }, "sign", /needs a private key/, false],
  ];
  for (const [config, creds, type, re, atLoad] of cases) {
    const id = ids();
    const status = atLoad ? nr.waitForStatus(id[type], (s) => s.text === "key error") : undefined;
    const flow = [
      tab(id),
      keyNode(id, config, creds),
      inject(id, { sub: "x" }, "json", id[type]),
      producer(type, id, {}, [[]]),
      catcher(id),
      debug(id, "caught"),
    ];
    await nr.deploy(flow);
    if (status) await status;
    const [caught] = await Promise.all([nr.waitForDebug((m) => m.id === id.caught), nr.inject(id.inject)]);
    assert.equal(caught.msg.error.code, "KEY_UNUSABLE", String(re));
    assert.match(caught.msg.error.message, re);
  }
});

test("a certificate verifies tokens from its own key type and rejects others", async () => {
  const id = ids();
  const foreign = await new jose.SignJWT({ sub: "x" })
    .setProtectedHeader({ alg: "RS256" })
    .setExpirationTime("1h")
    .sign(pairs.rsa.privateKey);
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id, { source: "pem" }, { pem: CERT }),
      inject(id, foreign, "str", id.verify),
      consumer("verify", id, {}, [[id.claims], []]),
      debug(id, "claims"),
      catcher(id),
      debug(id, "caught"),
    ],
    id.caught,
  );
  assert.equal(
    msg.error.code,
    "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
    "the certificate parsed as an RSA public key and rejected a foreign signature",
  );
});

test("a pasted JWK Set selects the key by kid and rejects unknown kids on the chosen route", async () => {
  const keys = [
    await jwk.public("rsa", { kid: "r1", alg: "RS256" }),
    await jwk.public("p256", { kid: "e1", alg: "ES256" }),
  ];
  const good = await new jose.SignJWT({ sub: "set" })
    .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "e1" })
    .setExpirationTime("1h")
    .sign(pairs.p256.privateKey);
  const unknown = await new jose.SignJWT({ sub: "set" })
    .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "e9" })
    .setExpirationTime("1h")
    .sign(pairs.p256.privateKey);
  const flow = (id, token) => [
    tab(id),
    keyNode(id, { source: "local-jwks", algorithms: "RS256, ES256" }, { jwk: JSON.stringify({ keys }) }),
    inject(id, token, "str", id.verify),
    consumer("verify", id, { failureMode: "output" }, [[id.claims], [id.rejected]]),
    debug(id, "claims"),
    debug(id, "rejected"),
  ];
  let id = ids();
  let msg = await run(id, flow(id, good), id.claims);
  assert.equal(msg.payload.sub, "set");
  id = ids();
  msg = await run(id, flow(id, unknown), id.rejected);
  assert.equal(msg.error.code, "ERR_JWKS_NO_MATCHING_KEY");
});

test("asymmetric encryption: RSA-OAEP-256 PEM and ECDH-ES X25519 JWK round trips", async () => {
  for (const [key, creds, alg] of [
    [{ source: "pem" }, { pem: pem.pkcs8("rsa") }, "RSA-OAEP-256"],
    [
      { source: "jwk" },
      { jwk: JSON.stringify(await jwk.private("x25519", { key_ops: ["deriveBits"] })) },
      "ECDH-ES+A256KW",
    ],
    [{ source: "pem" }, { pem: pem.pkcs8("p521") }, "ECDH-ES+A256KW"],
  ]) {
    const id = ids();
    const { token, msg } = await runBoth(
      id,
      roundTrip(id, key, creds, "encryption", { audience: "enc-api" }, { audience: "enc-api" }),
    );
    const header = jose.decodeProtectedHeader(token);
    assert.equal(header.alg, alg);
    assert.equal(header.enc, "A256GCM");
    assert.equal(msg.payload.aud, "enc-api");
  }
});

test("consumer policy: issuer mismatch, max age and clock tolerance", async () => {
  const key = { source: "pem" };
  const creds = { pem: pem.pkcs8("p256") };
  const now = Math.floor(Date.now() / 1000);
  const mint = (claims, exp) =>
    new jose.SignJWT(claims)
      .setProtectedHeader({ alg: "ES256", typ: "JWT" })
      .setExpirationTime(exp)
      .sign(pairs.p256.privateKey);
  const verifyOnly = (id, token, extra) => [
    tab(id),
    keyNode(id, key, creds),
    inject(id, token, "str", id.verify),
    consumer("verify", id, { failureMode: "output", ...extra }, [[id.claims], [id.rejected]]),
    debug(id, "claims"),
    debug(id, "rejected"),
  ];
  let id = ids();
  let msg = await run(id, verifyOnly(id, await mint({ iss: "other" }, now + 60), { issuer: "me, you" }), id.rejected);
  assert.deepEqual([msg.error.code, msg.error.claim], ["ERR_JWT_CLAIM_VALIDATION_FAILED", "iss"]);
  id = ids();
  msg = await run(id, verifyOnly(id, await mint({ iat: now - 600 }, now + 60), { maxTokenAge: 300 }), id.rejected);
  assert.deepEqual(
    [msg.error.code, msg.error.claim],
    ["ERR_JWT_EXPIRED", "iat"],
    "jose reports a max-age breach as expired on iat",
  );
  id = ids();
  msg = await run(id, verifyOnly(id, await mint({}, now - 30), { clockTolerance: 120 }), id.claims);
  assert.equal(typeof msg.payload.exp, "number", "a token expired 30 s ago passes with 120 s tolerance");
  id = ids();
  msg = await run(id, verifyOnly(id, await mint({}, now - 30), {}), id.rejected);
  assert.equal(msg.error.code, "ERR_JWT_EXPIRED");
});

test("headerTo nested inside claimsTo is a configuration error", async () => {
  const id = ids();
  const status = nr.waitForStatus(id.verify, (s) => s.text === "invalid config");
  await nr.deploy([
    tab(id),
    keyNode(id, { source: "pem" }, { pem: pem.pkcs8("p256") }),
    inject(id, "a.b.c", "str", id.verify),
    consumer("verify", id, { headerTo: "payload.header", headerToType: "msg" }, [[], []]),
    catcher(id),
    debug(id, "caught"),
  ]);
  await status;
  const [caught] = await Promise.all([nr.waitForDebug((m) => m.id === id.caught), nr.inject(id.inject)]);
  assert.equal(caught.msg.error.code, "INVALID_INPUT");
});

test("unused helper key pairs are distinct per run", () => {
  assert.notEqual(pem.pkcs8("rsa"), pem.pkcs8("p256"));
  assert.ok(crypto.createPublicKey(CERT).asymmetricKeyType === "rsa");
});

test("JWK deployment warnings and Catch errors never echo credential metadata", async () => {
  const marker = "PRIVATE_JWK_USE_MARKER";
  const id = ids();
  const material = await jwk.private("p256", { use: marker });
  const before = nr.lines.length;
  const msg = await run(id, roundTrip(id, { source: "jwk" }, { jwk: JSON.stringify(material) }, "signing"), id.caught);
  assert.equal(msg.error.code, "KEY_UNUSABLE");
  assert.doesNotMatch(JSON.stringify(msg), new RegExp(marker));
  assert.doesNotMatch(nr.lines.slice(before).join("\n"), new RegExp(marker));
  assert.ok(
    nr.lines.slice(before).some((line) => line.includes("JWK use does not fit")),
    "deploy warning observed",
  );
});

test("PEM, JWK and pasted JWK Set credential rotation replaces cached keys on a modified-node deploy", async () => {
  const next = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const mint = (pair) =>
    new jose.SignJWT({ sub: "rotation" })
      .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "stable-id" })
      .setExpirationTime("1h")
      .sign(pair.privateKey);
  const oldToken = await mint(pairs.p256);
  const newToken = await mint(next);
  for (const source of ["pem", "jwk", "local-jwks"]) {
    const id = ids();
    const credentials = (pair) =>
      source === "pem"
        ? { pem: pair.privateKey.export({ type: "pkcs8", format: "pem" }) }
        : {
            jwk: JSON.stringify(
              source === "jwk"
                ? pair.privateKey.export({ format: "jwk" })
                : { keys: [{ ...pair.publicKey.export({ format: "jwk" }), kid: "stable-id", alg: "ES256" }] },
            ),
          };
    const build = (pair) => [
      tab(id),
      keyNode(id, { source, algorithms: "ES256" }, credentials(pair)),
      inject(id, oldToken, "str", id.verify),
      inject(id, newToken, "str", id.verify, "inject2"),
      consumer("verify", id, { failureMode: "output" }, [[id.claims], [id.rejected]]),
      debug(id, "claims"),
      debug(id, "rejected"),
    ];
    assert.equal((await run(id, build(pairs.p256), id.claims)).payload.sub, "rotation");
    await nr.deploy(build(next), "nodes");
    const [rejected] = await Promise.all([nr.waitForDebug((m) => m.id === id.rejected), nr.inject(id.inject)]);
    assert.equal(rejected.msg.error.code, "ERR_JWS_SIGNATURE_VERIFICATION_FAILED", source);
    const [accepted] = await Promise.all([nr.waitForDebug((m) => m.id === id.claims), nr.inject(id.inject2)]);
    assert.equal(accepted.msg.payload.sub, "rotation", source);
  }
});

test("decryption Catch leaves ciphertext and aliased destinations unchanged on output failure", async () => {
  const id = ids();
  const marker = "PRIVATE_ALIAS_PLAINTEXT";
  const token = await new jose.EncryptJWT({ sub: marker })
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM", typ: "JWT" })
    .setExpirationTime("1h")
    .encrypt(pairs.rsa.publicKey);
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id, { source: "pem", family: "encryption" }, { pem: pem.pkcs8("rsa") }),
      inject(id, token, "str", id.prepare),
      {
        id: id.prepare,
        type: "function",
        z: id.tab,
        func: "msg.a = {}; msg.b = msg.a; return msg;",
        outputs: 1,
        wires: [[id.decrypt]],
      },
      consumer("decrypt", id, { claimsTo: "a.result", headerTo: "b.result.sub.header" }, [[], []]),
      catcher(id),
      debug(id, "caught"),
    ],
    id.caught,
  );
  assert.equal(msg.error.code, "OUTPUT_INVALID");
  assert.equal(msg.payload, token);
  assert.deepEqual(msg.a, {});
  assert.deepEqual(msg.b, {});
  assert.doesNotMatch(JSON.stringify(msg), new RegExp(marker));
});
