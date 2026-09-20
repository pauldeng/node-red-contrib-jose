"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { coded } = require("../../lib/errors");
const { createInflight } = require("../../lib/inflight");

test("each tracked input completes exactly once, whichever side wins", () => {
  const calls = [];
  const inflight = createInflight();
  const finishA = inflight.track((e) => calls.push(["a", e?.code]));
  const finishB = inflight.track((e) => calls.push(["b", e?.code]));
  assert.equal(
    finishA(() => calls.push(["a", "ok"])),
    true,
  );
  assert.equal(
    finishA(() => calls.push(["a", "twice"])),
    false,
    "second finish is a no-op",
  );
  assert.equal(inflight.size, 1);
  assert.equal(inflight.closeAll(coded("NODE_CLOSING")), 1);
  assert.equal(
    finishB(() => calls.push(["b", "late"])),
    false,
    "late completion after close is a no-op",
  );
  assert.equal(inflight.closeAll(coded("NODE_CLOSING")), 0);
  assert.deepEqual(calls, [
    ["a", "ok"],
    ["b", "NODE_CLOSING"],
  ]);
});
