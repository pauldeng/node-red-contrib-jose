"use strict";
const { promisify } = require("node:util");
const jose = require("jose");
const { coded, sanitize } = require("../lib/errors");
const { createInflight } = require("../lib/inflight");
const { applyTimeModes, protectedHeader, assertSerializableClaims, parsePath, writeOutputs } = require("../lib/jwt");

module.exports = function (RED) {
  const evaluate = promisify(RED.util.evaluateNodeProperty);

  function JoseSignNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    const keyNode = RED.nodes.getNode(config.key);
    const inflight = createInflight();
    let closing = false;

    // Static configuration is validated once; a failure is reported on every input, never silently dropped.
    let setup;
    try {
      if (keyNode && (keyNode.type !== "jose-key" || typeof keyNode.keyFor !== "function")) throw coded("KEY_UNUSABLE");
      if ((config.tokenToType === undefined ? "msg" : config.tokenToType) !== "msg")
        throw coded("INVALID_INPUT", "tokenTo must be a message property");
      setup = {
        claims: config.claims === undefined ? "payload" : config.claims,
        claimsType: config.claimsType === undefined ? "msg" : config.claimsType,
        time: {
          expiryMode: config.expiryMode,
          ttlSeconds: config.ttlSeconds,
          expiresAt: config.expiresAt,
          notBeforeMode: config.notBeforeMode,
          notBeforeSeconds: config.notBeforeSeconds,
          notBeforeAt: config.notBeforeAt,
          issuedAt: config.issuedAt,
        },
        header: { typ: config.typ },
        tokenTo: parsePath(config.tokenTo === undefined ? "payload" : config.tokenTo, "tokenTo"),
      };
      const source = setup.claims;
      if (
        typeof source !== "string" ||
        source.trim() === "" ||
        !["msg", "flow", "global", "json", "jsonata"].includes(setup.claimsType)
      )
        throw coded("INVALID_INPUT", "invalid input source or type");
      applyTimeModes(setup.time, {}, 0);
      protectedHeader(setup.header, "HS256");
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
        const key = keyNode.keyFor("sign");
        const input = await evaluate(setup.claims, setup.claimsType, node, msg);
        if (closing) throw coded("NODE_CLOSING");
        stage = "claims";
        const now = Math.floor(Date.now() / 1000);
        const { claims, times } = applyTimeModes(setup.time, input, now);
        const header = protectedHeader(setup.header, keyNode.state.alg);
        const jwt = new jose.SignJWT(claims).setProtectedHeader(header);
        if (times.iat !== undefined) jwt.setIssuedAt(times.iat);
        if (times.exp !== undefined) jwt.setExpirationTime(times.exp);
        if (times.nbf !== undefined) jwt.setNotBefore(times.nbf);
        stage = "jose";
        let token;
        try {
          token = await jwt.sign(key);
        } catch (err) {
          if (!closing && err instanceof TypeError) {
            try {
              assertSerializableClaims({ ...claims, ...times });
            } catch {
              throw coded("INVALID_CLAIMS");
            }
          }
          throw err;
        }
        if (closing) throw coded("NODE_CLOSING");
        stage = "output";
        writeOutputs(RED, msg, [[setup.tokenTo, token]]);
        finish((complete) => {
          send(msg);
          complete();
        });
      } catch (err) {
        if (closing) {
          finish((complete) => complete(coded("NODE_CLOSING")));
          return;
        }
        const error = sanitize(err, stage);
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
  RED.nodes.registerType("jose-sign", JoseSignNode);
};
