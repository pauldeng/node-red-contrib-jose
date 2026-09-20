"use strict";
const jose = require("jose");
const { attach, consumerSetup, consume } = require("../lib/operation");

module.exports = function (RED) {
  function JoseVerifyNode(config) {
    RED.nodes.createNode(this, config);
    attach(RED, this, RED.nodes.getNode(config.key), {
      kind: "consume",
      purpose: "verify",
      family: "signing",
      setup: () =>
        consumerSetup(
          {
            tokenFrom: config.tokenFrom,
            tokenFromType: config.tokenFromType,
            stripBearer: config.stripBearer,
            typ: config.typ,
            requiredClaims: config.requiredClaims,
            audience: config.audience,
            issuer: config.issuer,
            subject: config.subject,
            clockTolerance: config.clockTolerance,
            maxTokenAge: config.maxTokenAge,
            claimsTo: config.claimsTo,
            claimsToType: config.claimsToType,
            headerTo: config.headerTo,
            headerToType: config.headerToType,
            failureMode: config.failureMode,
          },
          { stripBearer: true },
        ),
      run: (ctx) =>
        consume(ctx, (token, key, state, options) =>
          jose.jwtVerify(token, key, { ...options, algorithms: state.algorithms }),
        ),
    });
  }
  RED.nodes.registerType("jose-verify", JoseVerifyNode);
};
