"use strict";
// M2: dir/A256GCM encrypt and decrypt through real flows; failures never reveal decrypted claims.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const crypto = require("node:crypto");
const jose = require("jose");
const { startNodeRed } = require("../helpers/node-red");
const { CODES } = require("../../lib/errors");

const PKG = path.resolve(__dirname, "../..");
const SECRET = crypto.randomBytes(32);
const MARKER = "SECRET-CLAIM-MARKER-9c1e";
const CLAIMS = { sub: MARKER, role: "admin" };
const JWE = /^[\w-]+\.[\w-]*\.[\w-]+\.[\w-]+\.[\w-]+$/; // dir leaves the encrypted-key segment empty
let nr;
let seq = 0;

test.before(async () => {
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
const keyNode = (id, extra = {}, secret = SECRET) => ({
  id: id.key,
  type: "jose-key",
  name: "k",
  family: "encryption",
  source: "secret",
  alg: "auto",
  secretEncoding: "base64",
  ...extra,
  credentials: { secret: secret.toString("base64") },
});
const inject = (id, payload, payloadType, to) => ({
  id: id.inject,
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
const encrypt = (id, extra, wires) => ({
  id: id.encrypt,
  type: "jose-encrypt",
  z: id.tab,
  key: id.key,
  claims: "payload",
  claimsType: "msg",
  typ: "JWT",
  expiryMode: "ttl",
  ttlSeconds: 3600,
  issuedAt: true,
  notBeforeMode: "preserve",
  tokenTo: "payload",
  tokenToType: "msg",
  ...extra,
  wires,
});
const decrypt = (id, extra, wires) => ({
  id: id.decrypt,
  type: "jose-decrypt",
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
const jwe = (claims = CLAIMS, key = SECRET) =>
  new jose.EncryptJWT(claims)
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .encrypt(key);

async function run(id, flow, debugId) {
  await nr.deploy(flow);
  const [d] = await Promise.all([nr.waitForDebug((m) => m.id === debugId), nr.inject(id.inject)]);
  return d.msg;
}
const decryptOnly = (id, payload, extra = {}, keyExtra = {}, secret = SECRET) => [
  tab(id),
  keyNode(id, keyExtra, secret),
  inject(id, payload, "str", id.decrypt),
  decrypt(id, extra, [[id.claims], [id.rejected]]),
  debug(id, "claims"),
  debug(id, "rejected"),
  catcher(id),
  debug(id, "caught"),
];
const noMarker = (value, what) =>
  assert.doesNotMatch(JSON.stringify(value), new RegExp(MARKER), `${what} must not reveal claims`);

test("round trip: claims -> jose-encrypt -> jose-decrypt -> claims", async () => {
  const id = ids();
  await nr.deploy([
    tab(id),
    keyNode(id),
    inject(id, CLAIMS, "json", id.encrypt),
    encrypt(id, {}, [[id.token, id.decrypt]]),
    debug(id, "token", "payload"),
    decrypt(id, {}, [[id.claims], []]),
    debug(id, "claims"),
  ]);
  const [tokenMsg, claimsMsg] = await Promise.all([
    nr.waitForDebug((m) => m.id === id.token),
    nr.waitForDebug((m) => m.id === id.claims),
    nr.inject(id.inject),
  ]);
  assert.match(tokenMsg.msg, JWE);
  assert.deepEqual(jose.decodeProtectedHeader(tokenMsg.msg), { alg: "dir", enc: "A256GCM", typ: "JWT" });
  noMarker(tokenMsg.msg, "the token");
  const claims = claimsMsg.msg.payload;
  assert.equal(claims.sub, MARKER);
  assert.equal(claims.exp, claims.iat + 3600);
});

test("wrong key, truncated tag and a four-part token are rejections without decrypted data", async () => {
  const good = await jwe();
  const parts = good.split(".");
  const flipped = parts[3][0] === "A" ? "B" + parts[3].slice(1) : "A" + parts[3].slice(1);
  const cases = [
    [await jwe(CLAIMS, crypto.randomBytes(32)), "ERR_JWE_DECRYPTION_FAILED"], // wrong key
    [[...parts.slice(0, 3), flipped, parts[4]].join("."), "ERR_JWE_DECRYPTION_FAILED"], // ciphertext tampered
    [good.slice(0, -6), "ERR_JWE_INVALID"], // tag too short
    [parts.slice(0, 4).join("."), "ERR_JWE_INVALID"], // four parts
  ];
  for (const [token, code] of cases) {
    for (const failureMode of ["catch", "output"]) {
      const id = ids();
      const msg = await run(
        id,
        decryptOnly(id, token, { failureMode }),
        failureMode === "catch" ? id.caught : id.rejected,
      );
      assert.equal(msg.error.code, code);
      assert.equal(msg.error.message, `${failureMode === "catch" ? "Error: " : ""}${CODES[code]}`);
      assert.equal(msg.error.cause, undefined);
      noMarker(msg, failureMode);
    }
  }
  noMarker(nr.lines.join("\n"), "the runtime log");
});

test("an expired JWE is rejected on the second output with claim and reason but no claims", async () => {
  const id = ids();
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id),
      inject(id, CLAIMS, "json", id.encrypt),
      encrypt(id, { expiryMode: "absolute", expiresAt: 1 }, [[id.decrypt]]),
      decrypt(id, { failureMode: "output" }, [[id.claims], [id.rejected]]),
      debug(id, "claims"),
      debug(id, "rejected"),
    ],
    id.rejected,
  );
  assert.deepEqual(msg.error, {
    code: "ERR_JWT_EXPIRED",
    message: CODES.ERR_JWT_EXPIRED,
    claim: "exp",
    reason: "check_failed",
  });
  assert.match(msg.payload, JWE, "the token is left in place");
  noMarker(msg, "the rejected message");
  noMarker(nr.lines.join("\n"), "the runtime log");
});

test("a JWS given to jose-decrypt and a JWE given to jose-verify are invalid tokens", async () => {
  let id = ids();
  const jws = await new jose.SignJWT(CLAIMS).setProtectedHeader({ alg: "HS256" }).setExpirationTime("1h").sign(SECRET);
  let msg = await run(id, decryptOnly(id, jws), id.caught);
  assert.equal(msg.error.code, "ERR_JWE_INVALID");
  id = ids();
  msg = await run(
    id,
    [
      tab(id),
      keyNode(id, { family: "signing" }),
      inject(id, await jwe(), "str", id.verify),
      {
        id: id.verify,
        type: "jose-verify",
        z: id.tab,
        key: id.key,
        tokenFrom: "payload",
        tokenFromType: "msg",
        claimsTo: "payload",
        claimsToType: "msg",
        failureMode: "catch",
        wires: [[], []],
      },
      catcher(id),
      debug(id, "caught"),
    ],
    id.caught,
  );
  assert.equal(msg.error.code, "ERR_JWS_INVALID");
});

test("family mismatch and wrong secret sizes are KEY_UNUSABLE", async () => {
  let id = ids();
  const status = nr.waitForStatus(id.sign, (s) => s.text === "key error");
  await nr.deploy([
    tab(id),
    keyNode(id),
    inject(id, CLAIMS, "json", id.sign),
    {
      id: id.sign,
      type: "jose-sign",
      z: id.tab,
      key: id.key,
      claims: "payload",
      claimsType: "msg",
      tokenTo: "payload",
      tokenToType: "msg",
      wires: [[]],
    },
    catcher(id),
    debug(id, "caught"),
  ]);
  await status;
  const [caught] = await Promise.all([nr.waitForDebug((m) => m.id === id.caught), nr.inject(id.inject)]);
  assert.equal(caught.msg.error.code, "KEY_UNUSABLE");
  assert.match(caught.msg.error.message, /configured for encryption, not sign/);

  id = ids();
  let msg = await run(id, decryptOnly(id, await jwe(), {}, {}, crypto.randomBytes(16)), id.caught);
  assert.equal(msg.error.code, "KEY_UNUSABLE");
  assert.match(msg.error.message, /exactly 32 bytes/);

  id = ids();
  msg = await run(id, decryptOnly(id, await jwe(), {}, { alg: "RSA-OAEP-256" }), id.caught);
  assert.equal(msg.error.code, "KEY_UNUSABLE");
  assert.match(msg.error.message, /RSA-OAEP-256 cannot be used with this key/);
});

test("Function-node claims and output containers work in encrypt/decrypt flows", async () => {
  const id = ids();
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id),
      inject(id, {}, "json", id.prepare),
      {
        id: id.prepare,
        type: "function",
        z: id.tab,
        func: 'msg.payload = {sub:"function-node"}; msg.result = {}; return msg;',
        outputs: 1,
        wires: [[id.encrypt]],
      },
      encrypt(id, {}, [[id.decrypt]]),
      decrypt(id, { claimsTo: "result.claims" }, [[id.result], []]),
      { ...catcher(id), wires: [[id.result]] },
      debug(id, "result"),
    ],
    id.result,
  );
  assert.equal(msg.error, undefined);
  assert.equal(msg.result.claims.sub, "function-node");
});

test("configured audience mismatch rejects JWE through both routes without plaintext", async () => {
  const token = await jwe({ ...CLAIMS, aud: "other-service" });
  for (const failureMode of ["catch", "output"]) {
    const id = ids();
    const flow = decryptOnly(id, token, { audience: "our-service", failureMode });
    // Observe any route so a failed policy check reports an assertion, not a timeout.
    const node = flow.find((n) => n.id === id.decrypt);
    node.wires = [[id.result], [id.result]];
    flow.find((n) => n.type === "catch").wires = [[id.result]];
    flow.push(debug(id, "result"));
    const msg = await run(id, flow, id.result);
    assert.equal(msg.error?.code, "ERR_JWT_CLAIM_VALIDATION_FAILED", failureMode);
    assert.equal(msg.error.cause, undefined);
    assert.equal(msg.payload, token);
    noMarker(msg, failureMode);
  }
  noMarker(nr.lines.join("\n"), "runtime log");
});

test("audience matches strings or arrays; blank disables and missing claims reject", async () => {
  for (const [claims, audience, code] of [
    [{ ...CLAIMS, aud: "service-b" }, "service-a, service-b", undefined],
    [{ ...CLAIMS, aud: ["other", "service-a"] }, "service-a", undefined],
    [CLAIMS, "", undefined],
    [CLAIMS, "service-a", "ERR_JWT_CLAIM_VALIDATION_FAILED"],
    [CLAIMS, null, "INVALID_INPUT"],
  ]) {
    const id = ids();
    const flow = decryptOnly(id, await jwe(claims), { audience });
    flow.find((n) => n.id === id.decrypt).wires = [[id.result], [id.result]];
    flow.find((n) => n.type === "catch").wires = [[id.result]];
    flow.push(debug(id, "result"));
    const msg = await run(id, flow, id.result);
    assert.equal(msg.error?.code, code);
    if (code) noMarker(msg, "failed audience check");
    else assert.equal(msg.payload.sub, MARKER);
  }
});

test("expired JWE Catch and unwritable output retain ciphertext only", async () => {
  const expired = await new jose.EncryptJWT({ ...CLAIMS, exp: 1 })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "JWT" })
    .encrypt(SECRET);
  for (const [token, options, code] of [
    [expired, {}, "ERR_JWT_EXPIRED"],
    [await jwe(), { claimsTo: "payload.claims", failureMode: "output" }, "OUTPUT_INVALID"],
  ]) {
    const id = ids();
    const msg = await run(id, decryptOnly(id, token, options), id.caught);
    assert.equal(msg.error.code, code);
    assert.equal(msg.payload, token);
    noMarker(msg, "Catch message");
  }
  noMarker(nr.lines.join("\n"), "runtime log");
});

test("decrypt binds both algorithms and rejects unsupported token headers", async () => {
  const parts = (await jwe()).split(".");
  for (const header of [
    { alg: "A256KW", enc: "A256GCM", typ: "JWT" },
    { alg: "dir", enc: "A128GCM", typ: "JWT" },
    { alg: "PBES2-HS256+A128KW", enc: "A256GCM", typ: "JWT", p2c: 999999999 },
  ]) {
    const id = ids();
    const token = [Buffer.from(JSON.stringify(header)).toString("base64url"), ...parts.slice(1)].join(".");
    const msg = await run(id, decryptOnly(id, token, { failureMode: "output" }), id.rejected);
    assert.equal(msg.error.code, "ERR_JOSE_ALG_NOT_ALLOWED");
    noMarker(msg, "algorithm rejection");
  }
});
