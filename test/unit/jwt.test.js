"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {
  applyTimeModes,
  protectedHeader,
  extractToken,
  consumeOptions,
  parsePath,
  assertDisjoint,
  preflight,
  writeOutputs,
  rejectMsg,
  MAX_TOKEN_BYTES,
} = require("../../lib/jwt");
const { util } = require("@node-red/util");

const NOW = 1_700_000_000;
const invalid = (re) => ({ code: "INVALID_INPUT", message: re });

test("expiry modes: ttl default, explicit, absolute (zero valid), preserve, omit", () => {
  const input = { sub: "a", exp: 5, nbf: 4, iat: 3 };
  assert.deepEqual(applyTimeModes({}, input, NOW), { claims: input, times: { exp: NOW + 3600, iat: NOW } });
  assert.equal(applyTimeModes({ ttlSeconds: "600" }, input, NOW).times.exp, NOW + 600, "editor strings are accepted");
  assert.equal(applyTimeModes({ expiryMode: "absolute", expiresAt: 0 }, input, NOW).times.exp, 0);
  const preserve = applyTimeModes({ expiryMode: "preserve", issuedAt: false }, input, NOW);
  assert.deepEqual(preserve, { claims: input, times: {} });
  const omit = applyTimeModes({ expiryMode: "omit", notBeforeMode: "omit" }, input, NOW);
  assert.deepEqual(omit.claims, { sub: "a", iat: 3 });
  assert.notEqual(omit.claims, input, "input object is never mutated");
  assert.deepEqual(input, { sub: "a", exp: 5, nbf: 4, iat: 3 });
});

test("not-before modes and issuedAt", () => {
  assert.equal(applyTimeModes({ notBeforeMode: "offset" }, {}, NOW).times.nbf, NOW, "offset default 0");
  assert.equal(applyTimeModes({ notBeforeMode: "offset", notBeforeSeconds: "-30" }, {}, NOW).times.nbf, NOW - 30);
  assert.equal(applyTimeModes({ notBeforeMode: "absolute", notBeforeAt: 7 }, {}, NOW).times.nbf, 7);
  assert.equal(applyTimeModes({ issuedAt: false }, {}, NOW).times.iat, undefined);
  assert.throws(() => applyTimeModes({ issuedAt: "yes" }, {}, NOW), invalid(/issuedAt/));
});

test("active-mode values must be present integers in range; inactive fields are ignored", () => {
  for (const [config, re] of [
    [{ ttlSeconds: "" }, /ttlSeconds/],
    [{ ttlSeconds: null }, /ttlSeconds/],
    [{ ttlSeconds: 0 }, /ttlSeconds/],
    [{ ttlSeconds: 1.5 }, /ttlSeconds/],
    [{ ttlSeconds: 31536001 }, /ttlSeconds/],
    [{ expiryMode: "absolute" }, /expiresAt is required/],
    [{ expiryMode: "absolute", expiresAt: -1 }, /expiresAt/],
    [{ expiryMode: "later" }, /unknown expiry mode/],
    [{ notBeforeMode: "offset", notBeforeSeconds: 31536001 }, /notBeforeSeconds/],
    [{ notBeforeMode: "absolute" }, /notBeforeAt is required/],
    [{ notBeforeMode: "soon" }, /unknown not-before mode/],
  ])
    assert.throws(() => applyTimeModes(config, {}, NOW), invalid(re), JSON.stringify(config));
  assert.equal(applyTimeModes({ expiryMode: "preserve", ttlSeconds: "garbage" }, {}, NOW).times.exp, undefined);
});

test("claims must be a plain object", () => {
  class Thing {}
  for (const bad of [undefined, null, "x", 1, [], Buffer.from("x"), new Thing(), new Date()])
    assert.throws(() => applyTimeModes({}, bad, NOW), { code: "INVALID_CLAIMS" }, String(bad));
  assert.ok(applyTimeModes({}, Object.create(null), NOW));
});

test("protected header: typ defaults to JWT, blank omits, alg from the key", () => {
  assert.deepEqual(protectedHeader({}, "HS256"), { alg: "HS256", typ: "JWT" });
  assert.deepEqual(protectedHeader({ typ: "" }, "HS256"), { alg: "HS256" });
  assert.deepEqual(protectedHeader({ typ: "at+jwt" }, "ES256", { kid: "k" }), {
    alg: "ES256",
    kid: "k",
    typ: "at+jwt",
  });
  assert.throws(() => protectedHeader({ typ: 5 }, "HS256"), invalid(/typ/));
});

test("extractToken: bounded, Bearer-stripped, compact-shaped", () => {
  const tok = "eyJhbGciOiJIUzI1NiJ9.e30.sig";
  assert.equal(extractToken(tok, true), tok);
  assert.equal(extractToken(`Bearer ${tok}`, true), tok);
  assert.equal(extractToken(`bearer   ${tok}`, true), tok, "case-insensitive, several spaces");
  assert.equal(extractToken("a.b.c.d.e", false), "a.b.c.d.e", "five-part JWE");
  for (const [value, strip, re] of [
    [`Bearer ${tok}`, false, /not a compact/],
    [`Basic ${tok}`, true, /not a compact/],
    [`Bearer ${tok} extra`, true, /not a compact/],
    [`${tok}\n`, true, /not a compact/],
    [` ${tok}`, true, /not a compact/],
    ["a.b", true, /not a compact/],
    ["", true, /no usable token/],
    [undefined, true, /no usable token/],
    [123, true, /no usable token/],
    [Buffer.from(tok), true, /no usable token/],
  ])
    assert.throws(() => extractToken(value, strip), { code: "NO_TOKEN", message: re }, String(value));
  assert.throws(() => extractToken("a".repeat(MAX_TOKEN_BYTES + 1), true), { code: "INPUT_TOO_LARGE" });
});

test("consumeOptions: typ and requiredClaims defaults and clearing", () => {
  assert.deepEqual(consumeOptions({}), { typ: "JWT", requiredClaims: ["exp"] });
  assert.deepEqual(consumeOptions({ typ: "", requiredClaims: "" }), {});
  assert.deepEqual(consumeOptions({ requiredClaims: " exp, sub ,, aud " }).requiredClaims, ["exp", "sub", "aud"]);
  assert.throws(() => consumeOptions({ requiredClaims: ["exp"] }), invalid(/requiredClaims/));
});

test("consumeOptions: issuer, subject, clockTolerance and maxTokenAge", () => {
  assert.deepEqual(consumeOptions({ issuer: " a , b ", subject: " me ", clockTolerance: "30", maxTokenAge: 600 }), {
    typ: "JWT",
    requiredClaims: ["exp"],
    issuer: ["a", "b"],
    subject: " me ",
    clockTolerance: 30,
    maxTokenAge: 600,
  });
  assert.equal(consumeOptions({ issuer: "one" }).issuer, "one");
  const blank = consumeOptions({ issuer: "", subject: "", clockTolerance: "", maxTokenAge: "" });
  assert.deepEqual(Object.keys(blank).sort(), ["requiredClaims", "typ"]);
  for (const [config, re] of [
    [{ issuer: null }, /issuer/],
    [{ issuer: " , " }, /issuer must contain/],
    [{ subject: 5 }, /subject/],
    [{ clockTolerance: 301 }, /clockTolerance/],
    [{ clockTolerance: -1 }, /clockTolerance/],
    [{ clockTolerance: null }, /clockTolerance/],
    [{ maxTokenAge: 0 }, /maxTokenAge/],
    [{ maxTokenAge: "x" }, /maxTokenAge/],
  ])
    assert.throws(() => consumeOptions(config), invalid(re), JSON.stringify(config));
});

test("paths: identifier segments only, no __proto__, disjoint", () => {
  assert.deepEqual(parsePath("payload.token", "tokenTo"), ["payload", "token"]);
  for (const bad of ["", "payload.", ".x", "payload[0]", "a b", "payload.__proto__.x", 5, undefined])
    assert.throws(() => parsePath(bad, "tokenTo"), invalid(/tokenTo/), String(bad));
  assertDisjoint(["payload", "a"], ["payload", "ab"], ["claimsTo", "headerTo"]);
  assert.throws(() => assertDisjoint(["payload"], ["payload"], ["claimsTo", "headerTo"]), invalid(/same or nested/));
  assert.throws(
    () => assertDisjoint(["payload"], ["payload", "x"], ["claimsTo", "headerTo"]),
    invalid(/same or nested/),
  );
});

test("preflight rejects scalar, array, accessor, frozen, sealed and read-only destinations without mutating", () => {
  const frozen = { payload: Object.freeze({}) };
  const sealed = { payload: Object.seal({ other: 1 }) };
  const readOnly = { payload: {} };
  Object.defineProperty(readOnly.payload, "claims", {
    value: 1,
    writable: false,
    enumerable: true,
    configurable: true,
  });
  const accessor = { payload: {} };
  Object.defineProperty(accessor.payload, "claims", { get: () => 1, enumerable: true });
  for (const [msg, path, re] of [
    [{ payload: "scalar" }, "payload.claims", /not a plain object/],
    [{ payload: [] }, "payload.claims", /not a plain object/],
    [{ payload: null }, "payload.claims", /not a plain object/],
    [frozen, "payload.claims", /cannot create/],
    [sealed, "payload.claims", /cannot create/],
    [readOnly, "payload.claims", /read-only/],
    [accessor, "payload.claims", /accessor/],
    [Object.freeze({}), "payload", /cannot create/],
  ]) {
    const before = JSON.stringify(msg);
    assert.throws(() => preflight(msg, path.split(".")), { code: "OUTPUT_INVALID", message: re }, path);
    assert.equal(JSON.stringify(msg), before);
  }
  preflight({ payload: "scalar" }, ["payload"]);
  preflight({}, ["payload", "deep", "er"]);
  preflight({ payload: { claims: 1 } }, ["payload", "claims"]);
});

test("writeOutputs preflights every destination before the first write", () => {
  const RED = { util };
  const msg = { payload: "token", req: {} };
  assert.throws(
    () =>
      writeOutputs(RED, msg, [
        [["header"], { alg: "HS256" }],
        [["payload", "claims"], {}],
      ]),
    { code: "OUTPUT_INVALID" },
  );
  assert.deepEqual(msg, { payload: "token", req: {} }, "nothing written when a later destination is invalid");
  writeOutputs(RED, msg, [
    [["header"], { alg: "HS256" }],
    [["payload"], { sub: "a" }],
  ]);
  assert.deepEqual(msg, { payload: { sub: "a" }, req: {}, header: { alg: "HS256" } });
});

test("rejectMsg shapes msg.error and preserves a previous error", () => {
  const err = Object.assign(new Error("m"), {
    code: "ERR_JWT_EXPIRED",
    claim: "exp",
    reason: "check_failed",
    cause: { payload: 1 },
  });
  const msg = rejectMsg({ payload: "t", error: { code: "OLD" } }, err);
  assert.deepEqual(msg, {
    payload: "t",
    _error: { code: "OLD" },
    error: { code: "ERR_JWT_EXPIRED", message: "m", claim: "exp", reason: "check_failed" },
  });
  assert.deepEqual(rejectMsg({}, Object.assign(new Error("m"), { code: "NO_TOKEN" })).error, {
    code: "NO_TOKEN",
    message: "m",
  });
});

test("plain objects from a Function sandbox are accepted for claims and output paths", () => {
  const vm = require("node:vm");
  const payload = vm.runInNewContext('({ sub: "sandbox" })');
  assert.equal(applyTimeModes({}, payload, NOW).claims.sub, "sandbox");
  const msg = vm.runInNewContext("({ result: {} })");
  writeOutputs({ util }, msg, [[["result", "claims"], { sub: "sandbox" }]]);
  assert.equal(msg.result.claims.sub, "sandbox");
  for (const expression of ["new (class Thing {})()", "new (class Object {})()", "Object.create({})", "new Date()"]) {
    const bad = vm.runInNewContext(expression);
    assert.throws(() => applyTimeModes({}, bad, NOW), { code: "INVALID_CLAIMS" }, expression);
    assert.throws(() => preflight({ result: bad }, ["result", "claims"]), { code: "OUTPUT_INVALID" }, expression);
  }
});

test("audience policy is static, optional, comma-separated and rejects invalid types", () => {
  assert.deepEqual(consumeOptions({ audience: " api, worker " }).audience, ["api", "worker"]);
  assert.equal(consumeOptions({ audience: "api" }).audience, "api");
  for (const audience of [undefined, "", "  "]) assert.equal(consumeOptions({ audience }).audience, undefined);
  for (const audience of [null, [], {}, false, 0, ", ,"]) {
    assert.throws(() => consumeOptions({ audience }), { code: "INVALID_INPUT" });
  }
});

test("consumer policy preserves exact subjects and permits the documented max-age range", () => {
  assert.equal(consumeOptions({ subject: " alice " }).subject, " alice ");
  assert.equal(consumeOptions({ maxTokenAge: 31536001 }).maxTokenAge, 31536001);
});

test("canonical output paths preserve one optional msg prefix and check the actual destination", () => {
  for (const [path, expected] of [
    ["result", ["result"]],
    ["msg.result", ["result"]],
    ["msg.msg.result", ["msg", "result"]],
    ["msg", ["msg"]],
  ]) {
    const segments = parsePath(path, "tokenTo");
    assert.deepEqual(segments, expected);
    const msg = {};
    writeOutputs({ util }, msg, [[segments, "value"]]);
    assert.equal(util.getObjectProperty(msg, expected.join(".")), "value");
  }
  for (const payload of ["scalar", Object.freeze({}), Object.seal({})]) {
    const msg = { payload };
    assert.throws(() => writeOutputs({ util }, msg, [[parsePath("msg.payload.claims", "claimsTo"), {}]]), {
      code: "OUTPUT_INVALID",
    });
    assert.deepEqual(msg, { payload });
  }
});
