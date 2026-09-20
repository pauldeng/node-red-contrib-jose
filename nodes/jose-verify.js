"use strict";
const { promisify } = require("node:util");
const jose = require("jose");
const { coded, sanitize, REJECTION_CODES } = require("../lib/errors");
const { createInflight } = require("../lib/inflight");
const { extractToken, consumeOptions, parsePath, writeOutputs, rejectMsg } = require("../lib/jwt");

module.exports = function (RED) {
  const evaluate = promisify(RED.util.evaluateNodeProperty);

  function JoseVerifyNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    const keyNode = RED.nodes.getNode(config.key);
    const inflight = createInflight();
    let closing = false;

    let setup;
    try {
      if (keyNode && (keyNode.type !== "jose-key" || typeof keyNode.keyFor !== "function")) throw coded("KEY_UNUSABLE");
      const failureMode = config.failureMode === undefined ? "catch" : config.failureMode;
      if (!["catch", "output"].includes(failureMode))
        throw coded("INVALID_INPUT", "failureMode must be catch or output");
      const stripBearer = config.stripBearer === undefined ? true : config.stripBearer;
      if (typeof stripBearer !== "boolean") throw coded("INVALID_INPUT", "stripBearer must be true or false");
      if ((config.claimsToType === undefined ? "msg" : config.claimsToType) !== "msg")
        throw coded("INVALID_INPUT", "claimsTo must be a message property");
      setup = {
        tokenFrom: config.tokenFrom === undefined ? "payload" : config.tokenFrom,
        tokenFromType: config.tokenFromType === undefined ? "msg" : config.tokenFromType,
        stripBearer,
        options: consumeOptions({ typ: config.typ, requiredClaims: config.requiredClaims }),
        claimsTo: parsePath(config.claimsTo === undefined ? "payload" : config.claimsTo, "claimsTo"),
        failureMode,
      };
      const source = setup.tokenFrom;
      if (
        typeof source !== "string" ||
        source.trim() === "" ||
        !["msg", "flow", "global", "jsonata"].includes(setup.tokenFromType)
      )
        throw coded("INVALID_INPUT", "invalid input source or type");
    } catch (err) {
      setup = { error: sanitize(err, "evaluate") };
    }
    if (!keyNode) node.status({ fill: "red", shape: "ring", text: "no key" });
    else if (!keyNode.state?.ok || keyNode.state.family !== "signing")
      node.status({ fill: "red", shape: "ring", text: "key error" });
    else if (setup.error) node.status({ fill: "red", shape: "ring", text: "invalid config" });

    node.on("input", async (msg, send, done) => {
      const finish = inflight.track(done);
      let stage = "evaluate";
      try {
        if (closing) throw coded("NODE_CLOSING");
        if (setup.error) throw setup.error;
        if (!keyNode) throw coded("NO_KEY_CONFIG");
        const key = keyNode.keyFor("verify");
        const raw = await evaluate(setup.tokenFrom, setup.tokenFromType, node, msg);
        if (closing) throw coded("NODE_CLOSING");
        stage = "token";
        const token = extractToken(raw, setup.stripBearer);
        stage = "jose";
        const { payload } = await jose.jwtVerify(token, key, { ...setup.options, algorithms: [keyNode.state.alg] });
        if (closing) throw coded("NODE_CLOSING");
        stage = "output";
        writeOutputs(RED, msg, [[setup.claimsTo, payload]]);
        finish((complete) => {
          send([msg, null]);
          complete();
        });
      } catch (err) {
        if (closing) {
          finish((complete) => complete(coded("NODE_CLOSING")));
          return;
        }
        const error = sanitize(err, stage);
        if (setup.failureMode === "output" && REJECTION_CODES.has(error.code)) {
          finish((complete) => {
            send([null, rejectMsg(msg, error)]);
            complete();
          });
          return;
        }
        if (error.code === "INTERNAL_ERROR") node.debug(`${error.code} at stage ${stage}`);
        finish((complete) => complete(error));
      }
    });

    node.on("close", (removed, done) => {
      closing = true;
      inflight.closeAll(coded("NODE_CLOSING"));
      done();
    });
  }
  RED.nodes.registerType("jose-verify", JoseVerifyNode);
};
