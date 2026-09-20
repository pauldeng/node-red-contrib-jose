"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { util } = require("@node-red/util");
const { loadMaterial, keyFor } = require("../../lib/keys");
const state = loadMaterial({ source: "secret" }, { secret: crypto.randomBytes(32).toString("base64") });

function operation(type, config = {}, evaluate, key = { type: "jose-key", state, keyFor: (p) => keyFor(state, p) }) {
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

for (const type of ["sign", "verify"]) {
  test(`${type}: rejects explicit null options and unsupported input types`, async () => {
    const fields =
      type === "sign"
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
    const field = type === "sign" ? "claimsType" : "tokenFromType";
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

test("sign: clone and serialization failures have the claims error code", async () => {
  const cycle = {};
  cycle.self = cycle;
  for (const payload of [{ value: 1n }, cycle, { value() {} }, { exp: Infinity }]) {
    const { handlers } = operation("sign", { expiryMode: "preserve" });
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
