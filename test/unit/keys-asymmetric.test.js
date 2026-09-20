"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const jose = require("jose");
const { loadMaterial, keyFor, MAX_JWKS_KEYS } = require("../../lib/keys");
const { pairs, pem, jwk } = require("../helpers/keys");

const unusable = (re) => ({ code: "KEY_UNUSABLE", message: re });
const load = (config, credentials) => loadMaterial({ source: "pem", ...config }, credentials);
const cert = fs.readFileSync(path.join(__dirname, "../fixtures/test-certificate.pem"), "utf8");

test("pem: private keys resolve auto algorithms per key type and serve both purposes", async () => {
  const cases = [
    ["rsa", pem.pkcs8("rsa"), "RS256", "signing"],
    ["rsa", pem.pkcs1(), "RS256", "signing"],
    ["p256", pem.sec1(), "ES256", "signing"],
    ["p384", pem.pkcs8("p384"), "ES384", "signing"],
    ["p521", pem.pkcs8("p521"), "ES512", "signing"],
    ["ed25519", pem.pkcs8("ed25519"), "Ed25519", "signing"],
    ["rsa", pem.pkcs8("rsa"), "RSA-OAEP-256", "encryption"],
    ["p256", pem.pkcs8("p256"), "ECDH-ES+A256KW", "encryption"],
    ["x25519", pem.pkcs8("x25519"), "ECDH-ES+A256KW", "encryption"],
  ];
  for (const [name, text, alg, family] of cases) {
    const state = load({ family }, { pem: text });
    assert.equal(state.ok, true, `${name} ${family}: ${state.error?.message}`);
    assert.equal(state.alg, alg);
    assert.deepEqual(state.algorithms, [alg]);
    const priv = keyFor(state, family === "signing" ? "sign" : "decrypt");
    const pub = keyFor(state, family === "signing" ? "verify" : "encrypt");
    assert.equal(priv.type, "private");
    assert.equal(pub.type, "public");
    assert.equal(keyFor(state, family === "signing" ? "verify" : "encrypt"), pub, "same object every call");
    if (family === "signing") {
      const token = await new jose.SignJWT({ a: 1 }).setProtectedHeader({ alg }).sign(priv);
      assert.equal((await jose.jwtVerify(token, pub, { algorithms: [alg] })).payload.a, 1);
    } else {
      const token = await new jose.EncryptJWT({ a: 1 }).setProtectedHeader({ alg, enc: "A256GCM" }).encrypt(pub);
      assert.equal((await jose.jwtDecrypt(token, priv)).payload.a, 1);
    }
  }
});

test("pem: public keys and certificates verify or encrypt but cannot sign or decrypt", () => {
  for (const text of [pem.spki("rsa"), pem.rsaPublicPkcs1(), cert]) {
    const state = load({}, { pem: text });
    assert.equal(state.ok, true, state.error?.message);
    assert.equal(state.alg, "RS256");
    assert.equal(keyFor(state, "verify").type, "public");
    assert.throws(() => keyFor(state, "sign"), unusable(/needs a private key/));
  }
  const enc = load({ family: "encryption" }, { pem: pem.spki("p256") });
  assert.equal(enc.alg, "ECDH-ES+A256KW");
  assert.throws(() => keyFor(enc, "decrypt"), unusable(/needs a private key/));
});

test("pem: encrypted private keys need the right passphrase", () => {
  const text = pem.encrypted("rsa", "correct horse");
  assert.equal(load({}, { pem: text, passphrase: "correct horse" }).ok, true);
  assert.match(load({}, { pem: text }).error.message, /passphrase is required/);
  assert.match(load({}, { pem: text, passphrase: "" }).error.message, /passphrase is required/);
  assert.match(load({}, { pem: text, passphrase: "wrong" }).error.message, /passphrase is wrong/);
});

test("pem: explicit algorithms must fit the key; unsupported material is refused", () => {
  assert.equal(load({ alg: "PS512" }, { pem: pem.pkcs8("rsa") }).alg, "PS512");
  assert.equal(load({ alg: "ES256" }, { pem: pem.pkcs8("p256") }).alg, "ES256");
  for (const [config, creds, re] of [
    [{ alg: "ES256" }, { pem: pem.pkcs8("rsa") }, /ES256 cannot be used with this key/],
    [{ alg: "ES384" }, { pem: pem.pkcs8("p256") }, /ES384 cannot be used with this key/],
    [{ alg: "HS256" }, { pem: pem.pkcs8("rsa") }, /HS256 cannot be used with this key/],
    [{ alg: "RS256" }, { pem: pem.pkcs8("ed25519") }, /RS256 cannot be used with this key/],
    [{ family: "encryption" }, { pem: pem.pkcs8("ed25519") }, /Ed25519 keys cannot be used for encryption/],
    [{}, { pem: pem.pkcs8("x25519") }, /X25519 keys cannot be used for signing/],
    [{}, { pem: pem.pkcs8("rsa1024") }, /at least 2048 bits/],
    [{}, { pem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" }, /private key could not be parsed/],
    [
      {},
      { pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----" },
      /public key or certificate could not be parsed/,
    ],
    [{}, { pem: "not pem at all" }, /public key or certificate could not be parsed/],
    [{}, {}, /pem credential is empty/],
    [{}, { pem: "x".repeat(256 * 1024 + 1) }, /too large/],
  ]) {
    const state = load(config, creds);
    assert.equal(state.ok, false, JSON.stringify(config));
    assert.match(state.error.message, re);
  }
});

test("jwk: single keys are passed to jose as the JWK object with a derived public copy", async () => {
  const priv = await jwk.private("rsa", { kid: "k1" });
  const state = loadMaterial({ source: "jwk" }, { jwk: JSON.stringify(priv) });
  assert.equal(state.ok, true, state.error?.message);
  assert.deepEqual([state.alg, state.kid], ["RS256", "k1"]);
  assert.deepEqual(keyFor(state, "sign"), priv);
  const pub = keyFor(state, "verify");
  assert.equal(pub.d, undefined);
  assert.equal(pub.p, undefined);
  assert.equal(pub.kid, "k1");
  const token = await new jose.SignJWT({ a: 1 })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .sign(keyFor(state, "sign"));
  assert.equal((await jose.jwtVerify(token, pub, { algorithms: ["RS256"] })).payload.a, 1);
  for (const [name, alg, family] of [
    ["p256", "ES256", "signing"],
    ["p521", "ES512", "signing"],
    ["ed25519", "Ed25519", "signing"],
    ["rsa", "RSA-OAEP-256", "encryption"],
    ["p384", "ECDH-ES+A256KW", "encryption"],
    ["x25519", "ECDH-ES+A256KW", "encryption"],
  ]) {
    const s = loadMaterial({ source: "jwk", family }, { jwk: JSON.stringify(await jwk.private(name)) });
    assert.equal(s.ok, true, `${name}: ${s.error?.message}`);
    assert.equal(s.alg, alg);
  }
  const publicOnly = loadMaterial({ source: "jwk" }, { jwk: JSON.stringify(await jwk.public("p256")) });
  assert.equal(keyFor(publicOnly, "verify").kty, "EC");
  assert.throws(() => keyFor(publicOnly, "sign"), unusable(/needs a private key/));
});

test("jwk: declared alg, use and key_ops are honoured", async () => {
  const withAlg = loadMaterial({ source: "jwk" }, { jwk: JSON.stringify(await jwk.private("rsa", { alg: "PS256" })) });
  assert.equal(withAlg.alg, "PS256", "declared alg wins over auto");
  assert.match(
    loadMaterial({ source: "jwk", alg: "RS256" }, { jwk: JSON.stringify(await jwk.private("rsa", { alg: "PS256" })) })
      .error.message,
    /differs from the JWK alg/,
  );
  assert.match(
    loadMaterial({ source: "jwk" }, { jwk: JSON.stringify(await jwk.private("rsa", { alg: "ES256" })) }).error.message,
    /does not fit/,
  );
  assert.match(
    loadMaterial({ source: "jwk" }, { jwk: JSON.stringify(await jwk.private("rsa", { use: "enc" })) }).error.message,
    /use does not fit the configured family/,
  );
  const signOnly = loadMaterial(
    { source: "jwk" },
    { jwk: JSON.stringify(await jwk.private("rsa", { key_ops: ["sign"] })) },
  );
  assert.equal(signOnly.ok, true);
  assert.equal(keyFor(signOnly, "sign").key_ops[0], "sign");
  assert.throws(() => keyFor(signOnly, "verify"), unusable(/key_ops do not permit verify/));
  const both = loadMaterial(
    { source: "jwk" },
    { jwk: JSON.stringify(await jwk.private("rsa", { key_ops: ["sign", "verify"] })) },
  );
  assert.deepEqual(keyFor(both, "verify").key_ops, ["verify"]);
});

test("jwk: oct keys follow the secret rules and the dir alg convention", () => {
  const k = (bytes, extra = {}) =>
    JSON.stringify({ kty: "oct", k: crypto.randomBytes(bytes).toString("base64url"), ...extra });
  const hs = loadMaterial({ source: "jwk" }, { jwk: k(32) });
  assert.deepEqual([hs.alg, hs.keys.kind], ["HS256", "oct"]);
  assert.equal(keyFor(hs, "sign").kty, "oct", "the JWK object itself goes to jose");
  assert.match(loadMaterial({ source: "jwk" }, { jwk: k(5) }).error.message, /at least 32 bytes/);
  assert.match(
    loadMaterial({ source: "jwk" }, { jwk: JSON.stringify({ kty: "oct", k: "YR" }) }).error.message,
    /not canonical base64url/,
  );
  const dir = loadMaterial({ source: "jwk", family: "encryption" }, { jwk: k(32, { alg: "A256GCM" }) });
  assert.equal(dir.alg, "dir", "a JWK alg of A256GCM means dir/A256GCM");
  assert.match(loadMaterial({ source: "jwk", family: "encryption" }, { jwk: k(16) }).error.message, /exactly 32 bytes/);
  assert.match(
    loadMaterial({ source: "jwk", family: "encryption" }, { jwk: k(32, { alg: "dir" }) }).error.message,
    /alg must be A256GCM/,
  );
});

test("jwk: malformed input is refused with a category, never echoed", async () => {
  for (const [text, re] of [
    ["not json", /not a JSON object/],
    ["[]", /not a JSON object/],
    ["{}", /has no kty/],
    [JSON.stringify({ kty: "XYZ" }), /unsupported JWK key type/],
    [JSON.stringify({ kty: "EC", crv: "secp256k1", x: "a", y: "b" }), /unsupported elliptic curve/],
    [JSON.stringify({ kty: "OKP", crv: "Ed448", x: "a" }), /unsupported OKP curve/],
    [JSON.stringify({ kty: "RSA", n: crypto.randomBytes(128).toString("base64url"), e: "AQAB" }), /at least 2048 bits/],
    [JSON.stringify({ keys: [await jwk.public("rsa")] }), /use the local-jwks source/],
    [JSON.stringify(await jwk.private("rsa", { key_ops: "sign" })), /key_ops must be an array of unique strings/],
  ]) {
    const state = loadMaterial({ source: "jwk" }, { jwk: text });
    assert.equal(state.ok, false, text.slice(0, 40));
    assert.match(state.error.message, re);
    assert.doesNotMatch(state.error.message, /AQAB|secp256k1/);
  }
});

test("local-jwks: public asymmetric members, an explicit algorithm list, verify only", async () => {
  const keys = [
    await jwk.public("rsa", { kid: "r1", alg: "RS256" }),
    await jwk.public("p256", { kid: "e1", alg: "ES256" }),
  ];
  const state = loadMaterial({ source: "local-jwks", algorithms: "RS256, ES256" }, { jwk: JSON.stringify({ keys }) });
  assert.equal(state.ok, true, state.error?.message);
  assert.deepEqual(state.algorithms, ["RS256", "ES256"]);
  const resolver = keyFor(state, "verify");
  assert.equal(typeof resolver, "function");
  const token = await new jose.SignJWT({ a: 1 })
    .setProtectedHeader({ alg: "ES256", kid: "e1" })
    .sign(pairs.p256.privateKey);
  assert.equal((await jose.jwtVerify(token, resolver, { algorithms: state.algorithms })).payload.a, 1);
  assert.throws(() => keyFor(state, "sign"), unusable(/can only verify/));
  const single = loadMaterial(
    { source: "local-jwks", algorithms: "RS256" },
    { jwk: JSON.stringify({ keys: [await jwk.public("rsa")] }) },
  );
  assert.equal(single.ok, true, "one algorithm: members may omit alg");
});

test("local-jwks: rejects private or symmetric members, missing or unfit algorithm lists", async () => {
  const pub = await jwk.public("rsa");
  for (const [config, keys, re] of [
    [{ algorithms: "RS256" }, [await jwk.private("rsa")], /must not contain private material/],
    [{ algorithms: "RS256" }, [{ kty: "oct", k: "AAAA" }], /must be public asymmetric keys/],
    [{ algorithms: "" }, [pub], /needs an explicit algorithm list/],
    [{}, [pub], /needs an explicit algorithm list/],
    [{ algorithms: "HS256" }, [pub], /only contain asymmetric JWS algorithms/],
    [{ algorithms: "RS256, nope" }, [pub], /only contain asymmetric JWS algorithms/],
    [{ algorithms: "RS256, ES256" }, [pub], /every JWK Set member must declare its alg/],
    [{ algorithms: "ES256" }, [pub], /does not fit the configured algorithm/],
    [{ algorithms: "RS256" }, [{ ...pub, alg: "PS256" }], /outside the configured list/],
    [{ algorithms: "RS256" }, [], /has no keys/],
    [{ algorithms: "RS256" }, Array.from({ length: MAX_JWKS_KEYS + 1 }, () => pub), /more than 100 keys/],
    [{ algorithms: "RS256", family: "encryption" }, [pub], /can only verify signatures/],
  ]) {
    const state = loadMaterial({ source: "local-jwks", ...config }, { jwk: JSON.stringify({ keys }) });
    assert.equal(state.ok, false, JSON.stringify(config));
    assert.match(state.error.message, re);
  }
});

test("jwk: credential metadata never enters diagnostics", async () => {
  for (const source of ["jwk", "local-jwks"]) {
    for (const material of [await jwk.public("rsa"), { kty: "oct", k: crypto.randomBytes(32).toString("base64url") }]) {
      material.use = "PRIVATE_METADATA_MARKER";
      const state = loadMaterial(
        { source, algorithms: "RS256" },
        {
          jwk: JSON.stringify(source === "local-jwks" ? { keys: [material] } : material),
        },
      );
      assert.equal(state.ok, false);
      assert.doesNotMatch(state.error.message, /PRIVATE_METADATA_MARKER/);
    }
  }
});

test("jwk: native parsing rejects padded weak RSA and malformed asymmetric material at deploy", async () => {
  const weak = await jwk.public("rsa1024");
  weak.n = Buffer.concat([Buffer.alloc(128), Buffer.from(weak.n, "base64url")]).toString("base64url");
  for (const material of [weak, { kty: "EC", crv: "P-256" }, { kty: "RSA", n: "AA", e: "AQAB" }]) {
    for (const source of ["jwk", "local-jwks"]) {
      const state = loadMaterial(
        { source, algorithms: material.kty === "EC" ? "ES256" : "RS256" },
        {
          jwk: JSON.stringify(source === "jwk" ? material : { keys: [material] }),
        },
      );
      assert.equal(state.ok, false, `${source} ${material.kty}`);
      assert.equal(state.error.code, "KEY_UNUSABLE");
    }
  }
});

test("jwk: private and derived public usages permit real crypto without granting excluded operations", async () => {
  for (const [name, family, ops] of [
    ["rsa", "signing", ["sign", "verify"]],
    ["p256", "signing", ["sign", "verify"]],
    ["ed25519", "signing", ["sign", "verify"]],
    ["rsa", "encryption", ["encrypt", "wrapKey", "decrypt", "unwrapKey"]],
    ["p256", "encryption", ["deriveBits"]],
    ["x25519", "encryption", ["deriveBits"]],
  ]) {
    const material = await jwk.private(name, { key_ops: ops });
    const state = loadMaterial({ source: "jwk", family }, { jwk: JSON.stringify(material) });
    assert.equal(state.ok, true);
    if (family === "signing") {
      const token = await new jose.SignJWT({ sub: "permitted" })
        .setProtectedHeader({ alg: state.alg })
        .sign(keyFor(state, "sign"));
      assert.equal((await jose.jwtVerify(token, keyFor(state, "verify"))).payload.sub, "permitted");
    } else {
      const token = await new jose.EncryptJWT({ sub: "permitted" })
        .setProtectedHeader({ alg: state.alg, enc: state.enc })
        .encrypt(keyFor(state, "encrypt"));
      assert.equal((await jose.jwtDecrypt(token, keyFor(state, "decrypt"))).payload.sub, "permitted");
    }
    for (const part of [state.keys.private, state.keys.public]) {
      assert.ok(
        part.key_ops.every((op) => ops.includes(op)),
        "no permission added",
      );
    }
  }
  for (const [family, ops, purpose] of [
    ["signing", ["sign"], "verify"],
    ["encryption", ["decrypt", "unwrapKey"], "encrypt"],
  ]) {
    const state = loadMaterial(
      { source: "jwk", family },
      { jwk: JSON.stringify(await jwk.private("rsa", { key_ops: ops })) },
    );
    assert.throws(() => keyFor(state, purpose), { code: "KEY_UNUSABLE" });
  }
});

test("all supported asymmetric signing algorithms round trip with a bound PEM key", async () => {
  for (const [name, alg] of [
    ...["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"].map((alg) => ["rsa", alg]),
    ["p256", "ES256"],
    ["p384", "ES384"],
    ["p521", "ES512"],
    ["ed25519", "Ed25519"],
  ]) {
    const state = loadMaterial({ source: "pem", alg }, { pem: pem.pkcs8(name) });
    assert.equal(state.ok, true);
    const token = await new jose.SignJWT({ alg }).setProtectedHeader({ alg }).sign(keyFor(state, "sign"));
    assert.equal(
      (await jose.jwtVerify(token, keyFor(state, "verify"), { algorithms: state.algorithms })).payload.alg,
      alg,
    );
  }
});
