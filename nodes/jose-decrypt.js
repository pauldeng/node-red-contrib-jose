"use strict";
const jose = require("jose");
const { attach, consumerSetup, consume } = require("../lib/operation");

module.exports = function (RED) {
  function JoseDecryptNode(config) {
    RED.nodes.createNode(this, config);
    attach(RED, this, RED.nodes.getNode(config.key), {
      kind: "consume",
      purpose: "decrypt",
      family: "encryption",
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
          { stripBearer: false },
        ),
      run: (ctx) =>
        consume(ctx, (token, key, state, options) =>
          jose.jwtDecrypt(token, key, {
            ...options,
            keyManagementAlgorithms: state.algorithms,
            contentEncryptionAlgorithms: [state.enc],
          }),
        ),
    });
  }
  RED.nodes.registerType("jose-decrypt", JoseDecryptNode);
};
