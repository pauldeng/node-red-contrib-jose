"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { util } = require("@node-red/util");
const { loadMaterial, keyFor } = require("../../lib/keys");
const states = {
  signing: loadMaterial({ source: "secret" }, { secret: crypto.randomBytes(32).toString("base64") }),
  encryption: loadMaterial(
    { family: "encryption", source: "secret" },
    { secret: crypto.randomBytes(32).toString("base64") },
  ),
};
const FAMILY = { sign: "signing", verify: "signing", encrypt: "encryption", decrypt: "encryption" };
const PRODUCERS = ["sign", "encrypt"];

function operation(type, config = {}, evaluate, key) {
  const state = states[FAMILY[type]];
  key ??= { type: "jose-key", state, keyFor: (p) => keyFor(state, p) };
  const handlers = {};
  const logs = [];
  let Constructor;
  require(`../../nodes/jose-${type}`)({
    nodes: {
      createNode(node) {
        node.on = (name, fn) => (handlers[name] = fn);
        node.status = () => {};
        node.debug = (text) => logs.push(text);
      },
      getNode: () => key,
      registerType: (_, ctor) => (Constructor = ctor),
    },
    util: { ...util, ...(evaluate ? { evaluateNodeProperty: evaluate } : {}) },
  });
  new Constructor(config);
  return { handlers, logs };
}

for (const type of ["sign", "verify", "encrypt", "decrypt"]) {
  test(`${type}: rejects explicit null options and unsupported input types`, async () => {
    const fields = PRODUCERS.includes(type)
      ? ["claims", "claimsType", "tokenTo", "tokenToType", "expiryMode", "notBeforeMode", "issuedAt", "typ"]
      : [
          "tokenFrom",
          "tokenFromType",
          "claimsTo",
          "claimsToType",
          "stripBearer",
          "failureMode",
          "typ",
          "requiredClaims",
          "audience",
        ];
    for (const field of fields) {
      const { handlers } = operation(type, { [field]: null });
      const done = [];
      await handlers.input(
        { payload: {} },
        () => assert.fail("invalid config sent a message"),
        (e) => done.push(e),
      );
      assert.equal(done.length, 1, field);
      assert.equal(done[0]?.code, "INVALID_INPUT", field);
    }
    const field = PRODUCERS.includes(type) ? "claimsType" : "tokenFromType";
    const { handlers } = operation(type, { [field]: "str" });
    const done = [];
    await handlers.input(
      {},
      () => assert.fail("unsupported input sent"),
      (e) => done.push(e),
    );
    assert.equal(done[0]?.code, "INVALID_INPUT");
  });

  test(`${type}: a reference to another node is catchable`, async () => {
    const { handlers } = operation(type, {}, undefined, { type: "inject" });
    const done = [];
    await handlers.input(
      {},
      () => assert.fail("wrong key sent"),
      (e) => done.push(e),
    );
    assert.equal(done[0]?.code, "KEY_UNUSABLE");
  });

  for (const late of ["resolve", "reject"]) {
    test(`${type}: close during evaluation settles once and ignores late ${late}`, async () => {
      let callback;
      const { handlers, logs } = operation(type, {}, (_value, _type, _node, _msg, cb) => {
        callback = cb;
      });
      const done = [];
      const pending = handlers.input(
        { payload: {} },
        () => assert.fail("sent after close"),
        (e) => done.push(e),
      );
      let closed = 0;
      handlers.close(false, () => closed++);
      assert.equal(closed, 1);
      assert.equal(done.length, 1);
      assert.equal(done[0].code, "NODE_CLOSING");
      callback(late === "reject" ? { code: "ERR_UNRECOGNIZED", message: "PRIVATE" } : null, {});
      await pending;
      assert.equal(done.length, 1);
      assert.deepEqual(logs, [], "no late diagnostics");
    });
  }
}

test("rejection with a read-only error property settles with OUTPUT_INVALID", async () => {
  const { handlers } = operation("verify", { failureMode: "output" });
  const msg = Object.defineProperty({ payload: "" }, "error", { value: "previous", writable: false });
  const done = [];
  await handlers.input(
    msg,
    () => assert.fail("unwritable rejection sent"),
    (e) => done.push(e),
  );
  assert.equal(done.length, 1);
  assert.equal(done[0]?.code, "OUTPUT_INVALID");
  assert.equal(msg.error, "previous");
  assert.equal(msg._error, undefined, "rejection writes are preflighted together");
});

test("a send failure still completes the input exactly once", async () => {
  const { handlers } = operation("sign");
  const done = [];
  await handlers.input(
    { payload: {} },
    () => {
      throw new Error("PRIVATE");
    },
    (e) => done.push(e),
  );
  assert.equal(done.length, 1);
  assert.equal(done[0]?.code, "OUTPUT_INVALID");
  assert.doesNotMatch(done[0].message, /PRIVATE/);
});

for (const type of PRODUCERS)
  test(`${type}: clone and serialization failures have the claims error code`, async () => {
    const cycle = {};
    cycle.self = cycle;
    for (const payload of [{ value: 1n }, cycle, { value() {} }, { exp: Infinity }]) {
      const { handlers } = operation(type, { expiryMode: "preserve" });
      const done = [];
      await handlers.input(
        { payload },
        () => assert.fail("unserializable claims sent"),
        (e) => done.push(e),
      );
      assert.equal(done.length, 1);
      assert.equal(done[0]?.code, "INVALID_CLAIMS");
    }
  });

for (const type of Object.keys(FAMILY)) {
  for (const late of ["resolve", "reject"]) {
    test(
      `${type}: close during crypto suppresses late ${late} without changing the message`,
      { timeout: 5000 },
      async (t) => {
        const jose = require("jose");
        const state = states[FAMILY[type]];
        const key = keyFor(state, type);
        let payload = { sub: "PRIVATE_CRYPTO_RESULT" };
        if (type === "verify")
          payload = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: "HS256", typ: "JWT" })
            .setExpirationTime("1h")
            .sign(key);
        if (type === "decrypt")
          payload = await new jose.EncryptJWT(payload)
            .setProtectedHeader({ alg: "dir", enc: "A256GCM", typ: "JWT" })
            .setExpirationTime("1h")
            .encrypt(key);
        const entered = Promise.withResolvers();
        const release = Promise.withResolvers();
        const subtle = crypto.webcrypto.subtle;
        const native = subtle[type];
        t.mock.method(subtle, type, async function (...args) {
          const result = await native.apply(this, args);
          entered.resolve();
          await release.promise;
          if (late === "reject") throw new DOMException("PRIVATE_CRYPTO_ERROR", "OperationError");
          return result;
        });
        const { handlers, logs } = operation(type, { failureMode: "output" });
        const msg = { payload, retained: "unchanged" };
        const done = [];
        const sent = [];
        const pending = handlers.input(
          msg,
          (value) => sent.push(value),
          (error) => done.push(error),
        );
        try {
          await entered.promise;
          let closed = 0;
          handlers.close(false, () => closed++);
          assert.equal(closed, 1);
          assert.equal(done.length, 1);
          assert.equal(done[0].code, "NODE_CLOSING");
        } finally {
          release.resolve();
          await pending;
        }
        assert.equal(done.length, 1);
        assert.deepEqual(sent, []);
        assert.deepEqual(logs, []);
        assert.deepEqual(msg, { payload, retained: "unchanged" });
      },
    );
  }
}

const jose = require("jose");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

for (const type of PRODUCERS)
  test(`${type}: claim setters from literals, message values, JSON arrays and random UUIDs`, async () => {
    const { handlers } = operation(type, {
      issuer: "issuer-x",
      subject: "who",
      subjectType: "msg",
      audience: '["a", "b"]',
      audienceType: "json",
      jti: "",
      jtiType: "uuid",
      kid: "k-1",
    });
    const sent = [];
    const done = [];
    await handlers.input(
      { payload: { role: "r", iss: "old" }, who: "alice" },
      (m) => sent.push(m),
      (e) => done.push(e),
    );
    assert.deepEqual(done, [undefined]);
    const token = sent[0].payload;
    assert.equal(jose.decodeProtectedHeader(token).kid, "k-1");
    const state = states[FAMILY[type]];
    const { payload } =
      type === "sign"
        ? await jose.jwtVerify(token, keyFor(state, "verify"), { algorithms: [state.alg] })
        : await jose.jwtDecrypt(token, keyFor(state, "decrypt"));
    assert.equal(payload.iss, "issuer-x", "setter overrides the incoming claim");
    assert.equal(payload.sub, "alice");
    assert.deepEqual(payload.aud, ["a", "b"]);
    assert.match(payload.jti, UUID);
    assert.equal(payload.role, "r");
  });

for (const type of PRODUCERS)
  test(`${type}: blank literals keep incoming claims; missing or non-string dynamic values fail`, async () => {
    let { handlers } = operation(type, { issuer: "", subject: "   ", expiryMode: "preserve", issuedAt: false });
    const sent = [];
    const state = states[FAMILY[type]];
    await handlers.input(
      { payload: { iss: "keep", sub: "s", exp: 4102444800 } },
      (m) => sent.push(m),
      () => {},
    );
    const { payload } =
      type === "sign"
        ? await jose.jwtVerify(sent[0].payload, keyFor(state, "verify"), { algorithms: [state.alg] })
        : await jose.jwtDecrypt(sent[0].payload, keyFor(state, "decrypt"));
    assert.deepEqual(payload, { iss: "keep", sub: "s", exp: 4102444800 });
    for (const config of [
      { issuer: "missing", issuerType: "msg" },
      { audience: "[]", audienceType: "json" },
      { audience: "[1]", audienceType: "json" },
      { subject: "num", subjectType: "msg" },
      { issuer: "x", issuerType: "jsonata" },
      { jti: null },
    ]) {
      ({ handlers } = operation(type, config));
      const done = [];
      await handlers.input(
        { payload: {}, num: 5 },
        () => assert.fail("sent"),
        (e) => done.push(e),
      );
      assert.equal(done[0]?.code, "INVALID_INPUT", JSON.stringify(config));
    }
  });

for (const type of ["verify", "decrypt"])
  test(`${type}: headerTo receives the protected header and must not nest with claimsTo`, async () => {
    const state = states[FAMILY[type]];
    const claims = { sub: "h" };
    const token =
      type === "verify"
        ? await new jose.SignJWT(claims)
            .setProtectedHeader({ alg: state.alg, typ: "JWT", kid: "kk" })
            .setExpirationTime("1h")
            .sign(keyFor(state, "sign"))
        : await new jose.EncryptJWT(claims)
            .setProtectedHeader({ alg: state.alg, enc: state.enc, typ: "JWT", kid: "kk" })
            .setExpirationTime("1h")
            .encrypt(keyFor(state, "encrypt"));
    let { handlers } = operation(type, { headerTo: "header" });
    const sent = [];
    await handlers.input(
      { payload: token },
      (m) => sent.push(m),
      () => {},
    );
    assert.equal(sent[0][0].header.kid, "kk");
    assert.equal(sent[0][0].header.alg, state.alg);
    assert.equal(sent[0][0].payload.sub, "h");
    ({ handlers } = operation(type, { claimsTo: "payload", headerTo: "payload.header" }));
    const done = [];
    await handlers.input(
      { payload: token },
      () => assert.fail("sent"),
      (e) => done.push(e),
    );
    assert.equal(done[0]?.code, "INVALID_INPUT");
  });

for (const type of ["verify", "decrypt"]) {
  test(`${type}: aliased output paths fail before attaching validated claims`, async () => {
    const state = states[FAMILY[type]];
    const builder =
      type === "verify"
        ? new jose.SignJWT({ sub: "PRIVATE_ALIAS_CLAIMS" })
        : new jose.EncryptJWT({ sub: "PRIVATE_ALIAS_CLAIMS" });
    builder
      .setProtectedHeader({ alg: state.alg, typ: "JWT", ...(state.enc ? { enc: state.enc } : {}) })
      .setExpirationTime("1h");
    const token =
      type === "verify" ? await builder.sign(keyFor(state, "sign")) : await builder.encrypt(keyFor(state, "encrypt"));
    const shared = {};
    const msg = { payload: token, a: shared, b: shared };
    const { handlers } = operation(type, { claimsTo: "a.result", headerTo: "b.result.sub.header" });
    const done = [];
    await handlers.input(
      msg,
      () => assert.fail("sent"),
      (e) => done.push(e),
    );
    assert.equal(done[0]?.code, "OUTPUT_INVALID");
    assert.deepEqual(shared, {}, "no decoded claims remain after output failure");
    assert.equal(msg.payload, token);
  });
}

for (const type of PRODUCERS) {
  test(`${type}: UUID mode works without a stored value`, async () => {
    const { handlers } = operation(type, { jtiType: "uuid" });
    const msg = { payload: {} };
    const done = [];
    await handlers.input(
      msg,
      () => {},
      (e) => done.push(e),
    );
    assert.deepEqual(done, [undefined]);
    const state = states[FAMILY[type]];
    const result =
      type === "sign"
        ? await jose.jwtVerify(msg.payload, keyFor(state, "verify"))
        : await jose.jwtDecrypt(msg.payload, keyFor(state, "decrypt"));
    assert.match(result.payload.jti, UUID);
  });
}

for (const type of PRODUCERS) {
  test(`${type}: overwritten unserialisable claims do not hide a key permission failure`, async () => {
    const family = FAMILY[type];
    const state = loadMaterial(
      { source: "jwk", family },
      {
        jwk: JSON.stringify({
          kty: "oct",
          k: crypto.randomBytes(32).toString("base64url"),
          key_ops: [type === "sign" ? "verify" : "decrypt"],
        }),
      },
    );
    const { handlers } = operation(type, { issuer: "replacement" }, undefined, {
      type: "jose-key",
      state,
      keyFor: (p) => keyFor(state, p),
    });
    const done = [];
    await handlers.input(
      { payload: { iss: 1n } },
      () => assert.fail("sent"),
      (e) => done.push(e),
    );
    assert.equal(done[0]?.code, "INVALID_INPUT", "the effective claims serialize; jose rejected key permissions");
  });
}
