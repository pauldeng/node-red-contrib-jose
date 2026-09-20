"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const jose = require("jose");
const { CODES, REJECTION_CODES, coded, sanitize } = require("../../lib/errors");

test("every code has exactly one troubleshooting row and every row is a code", () => {
  const doc = fs.readFileSync(path.join(__dirname, "../../docs/TROUBLESHOOTING.md"), "utf8");
  const rows = [...doc.matchAll(/^\| `([A-Z_]+)`\s+\| (Catch|rejection)\s+\|/gm)].map((m) => [m[1], m[2]]);
  assert.deepEqual(rows.map(([c]) => c).sort(), Object.keys(CODES).sort());
  for (const [code, route] of rows) assert.equal(route === "rejection", REJECTION_CODES.has(code), `${code} route`);
});

test("coded() builds package-owned errors and rejects unknown codes", () => {
  const err = coded("NO_TOKEN", "detail");
  assert.equal(err.code, "NO_TOKEN");
  assert.equal(err.message, `${CODES.NO_TOKEN}: detail`);
  assert.notEqual(sanitize(err, "anything"), err, "own errors are copied at the boundary");
  assert.throws(() => coded("NOPE"), /unknown error code/);
});

test("sanitize keeps jose codes with safe claim/reason and drops cause, payload and message", async () => {
  const key = new Uint8Array(32).fill(7);
  const jwe = await new jose.EncryptJWT({ sub: "SECRET-MARKER", exp: 1 })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .encrypt(key);
  let original;
  try {
    await jose.jwtDecrypt(jwe, key);
  } catch (e) {
    original = e;
  }
  assert.equal(original.cause.payload.sub, "SECRET-MARKER", "fixture: jose exposes the payload on cause");
  const out = sanitize(original, "jose");
  assert.notEqual(out, original);
  const { code, claim, reason, stage } = out;
  assert.deepEqual(
    { code, claim, reason, stage },
    { code: "ERR_JWT_EXPIRED", claim: "exp", reason: "check_failed", stage: "jose" },
  );
  assert.equal(out.message, CODES.ERR_JWT_EXPIRED);
  assert.equal(out.cause, undefined);
  assert.equal(out.payload, undefined);
  assert.doesNotMatch(JSON.stringify({ ...out, message: out.message, stack: out.stack }), /SECRET-MARKER/);
});

test("sanitize refuses unsafe claim names and unknown ERR_ codes", () => {
  const weird = Object.assign(new jose.errors.JWTClaimValidationFailed("x", {}, "exp", "check_failed"), {
    code: "ERR_JWT_CLAIM_VALIDATION_FAILED",
    claim: "a b\ninjected",
    reason: "check_failed",
  });
  const out = sanitize(weird, "jose");
  assert.equal(out.code, "ERR_JWT_CLAIM_VALIDATION_FAILED");
  assert.equal(out.claim, undefined);
  assert.equal(out.reason, "check_failed");
  const unknown = Object.assign(new Error("x"), { code: "ERR_SOMETHING_NEW" });
  assert.equal(sanitize(unknown, "jose").code, "INTERNAL_ERROR");
});

test("sanitize maps by stage and never copies the original text", () => {
  const marker = "TEST_SENSITIVE_INPUT";
  const cases = [
    [new Error(marker), "evaluate", "INVALID_INPUT"],
    [new TypeError(marker), "jose", "INVALID_INPUT"],
    [Object.assign(new Error(marker), { name: "DataCloneError" }), "jose", "INVALID_CLAIMS"],
    [new Error(marker), "claims", "INVALID_CLAIMS"],
    [new Error(marker), "output", "OUTPUT_INVALID"],
    [new Error(marker), "token", "INTERNAL_ERROR"],
    [marker, "jose", "INTERNAL_ERROR"],
    [{ code: "D3137", message: marker }, "evaluate", "INVALID_INPUT"],
    [undefined, "evaluate", "INVALID_INPUT"],
    [new Error(marker), "jose", "INVALID_INPUT"],
  ];
  for (const [input, stage, code] of cases) {
    const out = sanitize(input, stage);
    assert.equal(out.code, code, `${stage}: ${String(input)}`);
    assert.equal(out.stage, stage);
    assert.doesNotMatch(out.message, new RegExp(marker));
    assert.equal(out.cause, undefined);
  }
});

test("untrusted errors cannot choose routes or attach metadata", () => {
  const spoof = { code: "ERR_JWT_EXPIRED", claim: ["PRIVATE"], reason: "PRIVATE", message: "PRIVATE" };
  assert.equal(sanitize(spoof, "evaluate").code, "INVALID_INPUT");
  assert.equal(sanitize(spoof, "jose").code, "INTERNAL_ERROR");
  assert.doesNotMatch(JSON.stringify(sanitize(spoof, "jose")), /PRIVATE/);
  assert.throws(() => coded("constructor"));
  assert.throws(() => coded("toString"));
  const original = coded("KEY_UNUSABLE", "fixed diagnostic");
  const clean = sanitize(original, "evaluate");
  assert.notEqual(clean, original);
  assert.equal(clean.message, original.message);
  assert.equal(sanitize(clean).message, original.message, "repeated boundaries preserve package diagnostics");
  assert.equal(clean.cause, undefined);
});

test("jose metadata must be primitive reviewed values", () => {
  const original = new jose.errors.JWTClaimValidationFailed("PRIVATE", {}, "exp", "check_failed");
  original.claim = ["PRIVATE"];
  original.reason = "PRIVATE";
  const clean = sanitize(original, "jose");
  assert.equal(clean.claim, undefined);
  assert.equal(clean.reason, undefined);
});
