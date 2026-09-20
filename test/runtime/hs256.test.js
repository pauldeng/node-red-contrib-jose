"use strict";
// M1 tracer bullet: HS256 sign and verify through real flows, with the failure routes the contract promises.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const crypto = require("node:crypto");
const jose = require("jose");
const { startNodeRed } = require("../helpers/node-red");
const { CODES } = require("../../lib/errors");

const PKG = path.resolve(__dirname, "../..");
const SECRET = crypto.randomBytes(32);
const SECRET_B64 = SECRET.toString("base64");
const MARKER = "TEST_SENSITIVE_MARKER_7f3a";
const COMPACT = /^[\w-]+\.[\w-]+\.[\w-]+$/;
let nr;
let seq = 0;

test.before(async () => {
  process.env.JOSE_TEST_SECRET = SECRET_B64; // the harness passes process.env to the Node-RED child
  nr = await startNodeRed({
    packageDir: PKG,
    settings: { logging: { console: { level: "debug", metrics: false, audit: false } } },
  });
});
test.after(() => nr.stop());

// Unique ids per deploy so comms never replays a previous flow's status or debug messages.
const ids = () => {
  const n = ++seq;
  return new Proxy({}, { get: (_, k) => `${k}_${n}` });
};
const tab = (id) => ({ id: id.tab, type: "tab", label: id.tab });
const keyNode = (id, credentials = { secret: SECRET_B64 }, extra = {}) => ({
  id: id.key,
  type: "jose-key",
  name: "k",
  family: "signing",
  source: "secret",
  alg: "auto",
  secretEncoding: "base64",
  ...extra,
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
const sign = (id, extra, wires) => ({
  id: id.sign,
  type: "jose-sign",
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
const verify = (id, extra, wires) => ({
  id: id.verify,
  type: "jose-verify",
  z: id.tab,
  key: id.key,
  tokenFrom: "payload",
  tokenFromType: "msg",
  stripBearer: true,
  typ: "JWT",
  requiredClaims: "exp",
  claimsTo: "payload",
  claimsToType: "msg",
  failureMode: "catch",
  ...extra,
  wires,
});
const token = (alg = "HS256", claims = { sub: "alice" }, key = SECRET) =>
  new jose.SignJWT(claims).setProtectedHeader({ alg, typ: "JWT" }).setIssuedAt().setExpirationTime("1h").sign(key);

async function run(id, flow, debugId, injectName = "inject") {
  await nr.deploy(flow);
  const [d] = await Promise.all([nr.waitForDebug((m) => m.id === debugId), nr.inject(id[injectName])]);
  return d.msg;
}
const verifyOnly = (id, payload, extra = {}) => [
  tab(id),
  keyNode(id),
  inject(id, payload, "str", id.verify),
  verify(id, extra, [[id.claims], [id.rejected]]),
  debug(id, "claims"),
  debug(id, "rejected"),
  catcher(id),
  debug(id, "caught"),
];

test("round trip: claims -> jose-sign -> jose-verify -> claims", async () => {
  const id = ids();
  await nr.deploy([
    tab(id),
    keyNode(id),
    inject(id, { sub: "alice", role: "admin" }, "json", id.sign),
    sign(id, {}, [[id.token, id.verify]]),
    debug(id, "token", "payload"),
    verify(id, {}, [[id.claims], []]),
    debug(id, "claims"),
  ]);
  const [tokenMsg, claimsMsg] = await Promise.all([
    nr.waitForDebug((m) => m.id === id.token),
    nr.waitForDebug((m) => m.id === id.claims),
    nr.inject(id.inject),
  ]);
  assert.match(tokenMsg.msg, COMPACT);
  assert.deepEqual(jose.decodeProtectedHeader(tokenMsg.msg), { alg: "HS256", typ: "JWT" });
  const claims = claimsMsg.msg.payload;
  const now = Math.floor(Date.now() / 1000);
  assert.equal(claims.sub, "alice");
  assert.equal(claims.role, "admin");
  assert.ok(Math.abs(claims.iat - now) < 10, "iat is now");
  assert.equal(claims.exp, claims.iat + 3600);
  assert.equal(claimsMsg.msg.error, undefined);
});

test("tampered signature -> Catch with a stable code, package message and no cause", async () => {
  const id = ids();
  const good = await token();
  const bad = good.slice(0, -2) + (good.endsWith("A") ? "BB" : "AA");
  const msg = await run(id, verifyOnly(id, bad), id.caught);
  assert.equal(msg.error.code, "ERR_JWS_SIGNATURE_VERIFICATION_FAILED");
  // Catch formats Error objects with toString(), hence the "Error: " prefix; the second output carries the bare message.
  assert.equal(msg.error.message, `Error: ${CODES.ERR_JWS_SIGNATURE_VERIFICATION_FAILED}`);
  assert.equal(msg.error.cause, undefined);
  assert.equal(msg.error.source.type, "jose-verify");
});

test("expired token -> rejected output with msg.error and the token left in place", async () => {
  const id = ids();
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id),
      inject(id, { sub: "a" }, "json", id.sign),
      sign(id, { expiryMode: "absolute", expiresAt: 1 }, [[id.verify]]),
      verify(id, { failureMode: "output" }, [[id.claims], [id.rejected]]),
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
  assert.match(msg.payload, COMPACT);
  assert.equal(jose.decodeJwt(msg.payload).exp, 1);
});

test("a token signed with another algorithm is not allowed even with the same secret", async () => {
  const id = ids();
  const msg = await run(id, verifyOnly(id, await token("HS512")), id.caught);
  assert.equal(msg.error.code, "ERR_JOSE_ALG_NOT_ALLOWED");
});

test("Bearer prefix is stripped when enabled and rejected as NO_TOKEN when disabled", async () => {
  const good = await token();
  let id = ids();
  let msg = await run(id, verifyOnly(id, `Bearer ${good}`), id.claims);
  assert.equal(msg.payload.sub, "alice");
  id = ids();
  msg = await run(id, verifyOnly(id, `Bearer ${good}`, { stripBearer: false, failureMode: "output" }), id.rejected);
  assert.equal(msg.error.code, "NO_TOKEN");
});

test("short secret: dependent nodes show key error and every input fails KEY_UNUSABLE", async () => {
  const id = ids();
  const status = nr.waitForStatus(id.sign, (s) => s.text === "key error");
  await nr.deploy([
    tab(id),
    keyNode(id, { secret: crypto.randomBytes(16).toString("base64") }),
    inject(id, { sub: "a" }, "json", id.sign),
    sign(id, {}, [[id.claims]]),
    debug(id, "claims"),
    catcher(id),
    debug(id, "caught"),
  ]);
  await status;
  const [caught] = await Promise.all([nr.waitForDebug((m) => m.id === id.caught), nr.inject(id.inject)]);
  assert.equal(caught.msg.error.code, "KEY_UNUSABLE");
  assert.match(caught.msg.error.message, /HS256 needs a secret of at least 32 bytes/);
  assert.ok(
    nr.lines.some((l) => /\[warn\] \[jose-key:k\] .*at least 32 bytes/.test(l)),
    "key config warned once at deploy",
  );
});

test("non-canonical base64 and an unsupported imported algorithm are KEY_UNUSABLE", async () => {
  let id = ids();
  let msg = await run(
    id,
    [
      tab(id),
      keyNode(id, { secret: "YR==" }),
      inject(id, {}, "json", id.sign),
      sign(id, {}, [[]]),
      catcher(id),
      debug(id, "caught"),
    ],
    id.caught,
  );
  assert.equal(msg.error.code, "KEY_UNUSABLE");
  assert.match(msg.error.message, /not canonical base64/);
  id = ids();
  msg = await run(
    id,
    [
      tab(id),
      keyNode(id, undefined, { alg: "none" }),
      inject(id, {}, "json", id.sign),
      sign(id, {}, [[]]),
      catcher(id),
      debug(id, "caught"),
    ],
    id.caught,
  );
  assert.equal(msg.error.code, "KEY_UNUSABLE");
  assert.match(msg.error.message, /not supported for signing/);
});

test("operational faults still throw when rejections are routed to the second output", async () => {
  const id = ids();
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id, { secret: crypto.randomBytes(8).toString("base64") }),
      inject(id, await token(), "str", id.verify),
      verify(id, { failureMode: "output" }, [[id.claims], [id.rejected]]),
      debug(id, "claims"),
      debug(id, "rejected"),
      catcher(id),
      debug(id, "caught"),
    ],
    id.caught,
  );
  assert.equal(msg.error.code, "KEY_UNUSABLE");
});

test("credential from a whole-value environment reference; export shows neither", async () => {
  const id = ids();
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id, { secret: "${JOSE_TEST_SECRET}" }),
      inject(id, { sub: "env" }, "json", id.sign),
      sign(id, {}, [[id.verify]]),
      verify(id, {}, [[id.claims], []]),
      debug(id, "claims"),
    ],
    id.claims,
  );
  assert.equal(msg.payload.sub, "env");
  const exported = JSON.stringify(await nr.api("GET", "/flows"));
  assert.ok(
    !exported.includes(SECRET_B64) && !exported.includes("JOSE_TEST_SECRET"),
    "no secret or reference in the export",
  );
});

test("rotating the secret in a modified-node deploy invalidates old tokens and signs with the new one", async () => {
  const id = ids();
  const build = (secret, oldToken) => [
    tab(id),
    keyNode(id, { secret }),
    inject(id, { sub: "r" }, "json", id.sign),
    sign(id, {}, [[id.token, id.verify]]),
    debug(id, "token", "payload"),
    inject(id, oldToken, "str", id.verify, "inject2"),
    verify(id, {}, [[id.claims], []]),
    debug(id, "claims"),
    catcher(id),
    debug(id, "caught"),
  ];
  await nr.deploy(build(crypto.randomBytes(32).toString("base64"), "unused"));
  const [first] = await Promise.all([nr.waitForDebug((m) => m.id === id.token), nr.inject(id.inject)]);
  const oldToken = first.msg;
  await nr.deploy(build(crypto.randomBytes(32).toString("base64"), oldToken), "nodes");
  const [caught] = await Promise.all([nr.waitForDebug((m) => m.id === id.caught), nr.inject(id.inject2)]);
  assert.equal(caught.msg.error.code, "ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "old token fails after rotation");
  const [claims] = await Promise.all([nr.waitForDebug((m) => m.id === id.claims), nr.inject(id.inject)]);
  assert.equal(claims.msg.payload.sub, "r", "new secret signs and verifies");
});

test("a JSONata error never leaks the input, even at debug log level", async () => {
  const id = ids();
  const msg = await run(
    id,
    verifyOnly(id, MARKER, { tokenFrom: "$error(payload)", tokenFromType: "jsonata" }),
    id.caught,
  );
  assert.equal(msg.error.code, "INVALID_INPUT");
  assert.equal(msg.error.message, `Error: ${CODES.INVALID_INPUT}`);
  assert.equal(msg.error.cause, undefined);
  assert.doesNotMatch(nr.lines.join("\n"), new RegExp(MARKER));
});

test("scalar output parent -> OUTPUT_INVALID and the message is not modified", async () => {
  const id = ids();
  const msg = await run(
    id,
    [
      tab(id),
      keyNode(id),
      inject(id, "not-an-object", "str", id.sign),
      sign(id, { claims: '{"sub":"x"}', claimsType: "json", tokenTo: "payload.token" }, [[id.token]]),
      debug(id, "token"),
      catcher(id),
      debug(id, "caught"),
    ],
    id.caught,
  );
  assert.equal(msg.error.code, "OUTPUT_INVALID");
  assert.equal(msg.payload, "not-an-object");
});

test("native claims clone/serialization failures reach Catch as INVALID_CLAIMS", async () => {
  for (const value of [
    "{ value: 1n }",
    "{ value() {} }",
    "{ exp: Infinity }",
    "(() => { const x = {}; x.self = x; return x; })()",
  ]) {
    const id = ids();
    const msg = await run(
      id,
      [
        tab(id),
        keyNode(id),
        inject(id, {}, "json", id.make),
        {
          id: id.make,
          type: "function",
          z: id.tab,
          func: `msg.payload = ${value}; return msg;`,
          outputs: 1,
          wires: [[id.sign]],
        },
        sign(id, { expiryMode: "preserve" }, [[]]),
        catcher(id),
        debug(id, "caught", "error"),
      ],
      id.caught,
    );
    assert.equal(msg.code, "INVALID_CLAIMS");
    assert.equal(msg.cause, undefined);
  }
});

test("explicit null input policy is a configuration error even in rejection-output mode", async () => {
  const id = ids();
  const msg = await run(id, verifyOnly(id, await token(), { stripBearer: null, failureMode: "output" }), id.caught);
  assert.equal(msg.error.code, "INVALID_INPUT");
});

test("verify enforces static audience policy", async () => {
  for (const [aud, expected] of [
    ["other", "ERR_JWT_CLAIM_VALIDATION_FAILED"],
    ["service", undefined],
  ]) {
    const id = ids();
    const flow = verifyOnly(id, await token("HS256", { sub: "alice", aud }), {
      audience: "service",
      failureMode: "output",
    });
    flow.find((n) => n.id === id.verify).wires = [[id.result], [id.result]];
    flow.push(debug(id, "result"));
    const msg = await run(id, flow, id.result);
    assert.equal(msg.error?.code, expected);
  }
});
