"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { decodeSecret, loadMaterial, keyFor, SIGNING_ALGS, ENCRYPTION_ALGS, HMAC_MIN_BYTES } = require("../../lib/keys");

const bytes = (n, fill = 1) => Buffer.alloc(n, fill);
const unusable = (re) => ({ code: "KEY_UNUSABLE", message: re });

test("decodeSecret accepts only canonical input per encoding", () => {
  assert.deepEqual(decodeSecret("YQ==", "base64"), Buffer.from("a"));
  assert.throws(() => decodeSecret("YR==", "base64"), unusable(/not canonical base64/), "non-canonical pad bits");
  assert.throws(() => decodeSecret("YQ", "base64"), unusable(/not valid base64/), "missing padding");
  assert.throws(() => decodeSecret("!!!!", "base64"), unusable(/not valid base64/));
  assert.deepEqual(decodeSecret("YQ", "base64url"), Buffer.from("a"));
  assert.throws(
    () => decodeSecret("YQ==", "base64url"),
    unusable(/not valid base64url/),
    "padding is not canonical base64url",
  );
  assert.throws(() => decodeSecret("YR", "base64url"), unusable(/not canonical base64url/));
  assert.deepEqual(decodeSecret("00ff", "hex"), Buffer.from([0, 255]));
  assert.deepEqual(decodeSecret("00FF", "hex"), Buffer.from([0, 255]), "hex case is insignificant");
  assert.throws(() => decodeSecret("abc", "hex"), unusable(/not valid hex/), "odd length");
  assert.throws(() => decodeSecret("abzz", "hex"), unusable(/not valid hex/));
  assert.deepEqual(decodeSecret(" a\n", "utf8"), Buffer.from(" a\n"), "utf8 is exact bytes, no trimming");
  assert.throws(() => decodeSecret("", "utf8"), unusable(/empty/));
  assert.throws(() => decodeSecret(undefined, "base64"), unusable(/empty/));
  assert.throws(() => decodeSecret("YQ==", "ascii"), unusable(/unknown secret encoding/));
});

test("loadMaterial: secret source resolves HMAC algorithms with RFC 7518 minimum lengths", () => {
  for (const [alg, min] of Object.entries(HMAC_MIN_BYTES)) {
    const ok = loadMaterial(
      { family: "signing", source: "secret", alg, secretEncoding: "hex" },
      { secret: bytes(min).toString("hex") },
    );
    assert.equal(ok.ok, true, alg);
    assert.equal(ok.alg, alg);
    assert.deepEqual(ok.keys.secret, bytes(min));
    const short = loadMaterial(
      { family: "signing", source: "secret", alg, secretEncoding: "hex" },
      { secret: bytes(min - 1).toString("hex") },
    );
    assert.equal(short.ok, false);
    assert.match(short.error.message, new RegExp(`${alg} needs a secret of at least ${min} bytes`));
  }
  const auto = loadMaterial({ family: "signing", source: "secret" }, { secret: bytes(32).toString("base64") });
  assert.equal(auto.alg, "HS256", "auto -> HS256 and base64 is the default encoding");
  assert.equal(auto.enc, undefined);
  const rsa = loadMaterial(
    { family: "signing", source: "secret", alg: "RS256", secretEncoding: "utf8" },
    { secret: "x".repeat(32) },
  );
  assert.match(rsa.error.message, /RS256 cannot be used with this key/);
  const unknownAlg = loadMaterial(
    { family: "signing", source: "secret", alg: "none", secretEncoding: "utf8" },
    { secret: "x".repeat(32) },
  );
  assert.match(unknownAlg.error.message, /not supported for signing/);
});

test("loadMaterial: encryption family with a secret means dir/A256GCM with exactly 32 bytes", () => {
  const ok = loadMaterial(
    { family: "encryption", source: "secret", secretEncoding: "hex" },
    { secret: bytes(32).toString("hex") },
  );
  assert.deepEqual([ok.ok, ok.alg, ok.enc], [true, "dir", "A256GCM"]);
  const wrongLen = loadMaterial(
    { family: "encryption", source: "secret", secretEncoding: "hex" },
    { secret: bytes(16).toString("hex") },
  );
  assert.match(wrongLen.error.message, /exactly 32 bytes/);
  const wrongAlg = loadMaterial(
    { family: "encryption", source: "secret", alg: "RSA-OAEP-256", secretEncoding: "hex" },
    { secret: bytes(32).toString("hex") },
  );
  assert.match(wrongAlg.error.message, /RSA-OAEP-256 cannot be used with this key/);
});

test("loadMaterial never throws and names the failure category only", () => {
  for (const [config, creds, re] of [
    [{ family: "signing", source: "secret" }, {}, /empty/],
    [{ family: "signing", source: "secret" }, { secret: "YR==" }, /not canonical/],
    [{ family: "signing", source: "pem" }, { pem: "x" }, /could not be parsed/],
    [{ family: "signing", source: "remote-jwks" }, {}, /JWKS URL is empty/],
    [{ family: "signing", source: "nope" }, {}, /unknown key source/],
    [{ family: "both", source: "secret" }, { secret: "YQ==" }, /unknown key family/],
    [
      { family: "signing", source: "secret", secretEncoding: "utf8" },
      { secret: "x".repeat(256 * 1024 + 1) },
      /too large/,
    ],
  ]) {
    const state = loadMaterial(config, creds);
    assert.equal(state.ok, false);
    assert.equal(state.error.code, "KEY_UNUSABLE");
    assert.match(state.error.message, re);
    assert.doesNotMatch(state.error.message, /YR==|xxxx/, "no material in messages");
  }
});

test("keyFor enforces purpose against family and state", () => {
  const signing = loadMaterial(
    { family: "signing", source: "secret", secretEncoding: "hex" },
    { secret: bytes(32).toString("hex") },
  );
  assert.deepEqual(keyFor(signing, "sign"), bytes(32));
  assert.equal(keyFor(signing, "verify"), keyFor(signing, "sign"), "same object every call (jose caches by identity)");
  assert.throws(() => keyFor(signing, "encrypt"), unusable(/configured for signing, not encrypt/));
  assert.throws(() => keyFor(signing, "nope"), unusable(/unknown purpose/));
  const bad = loadMaterial({ family: "signing", source: "secret" }, {});
  assert.throws(() => keyFor(bad, "sign"), unusable(/empty/));
  assert.throws(() => keyFor(undefined, "sign"), { code: "KEY_UNUSABLE" });
});

test("editor algorithm lists match the runtime lists", () => {
  const html = fs.readFileSync(path.join(__dirname, "../../nodes/jose-key.html"), "utf8");
  for (const alg of [...SIGNING_ALGS, ...ENCRYPTION_ALGS])
    assert.ok(html.includes(`"${alg}"`), `${alg} missing from jose-key.html`);
});

test("absent key enums default; explicit null enums fail closed", () => {
  const credentials = { secret: bytes(32).toString("base64") };
  assert.equal(loadMaterial({}, credentials).ok, true);
  for (const field of ["source", "family", "alg", "secretEncoding"]) {
    const result = loadMaterial({ source: "secret", [field]: null }, credentials);
    assert.equal(result.ok, false, field);
    assert.equal(result.error.code, "KEY_UNUSABLE", field);
  }
});
