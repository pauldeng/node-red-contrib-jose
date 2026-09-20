"use strict";
const jose = require("jose");
const { attach, producerSetup, produce } = require("../lib/operation");

module.exports = function (RED) {
  function JoseSignNode(config) {
    RED.nodes.createNode(this, config);
    attach(RED, this, RED.nodes.getNode(config.key), {
      kind: "produce",
      purpose: "sign",
      family: "signing",
      setup: () =>
        producerSetup({
          claims: config.claims,
          claimsType: config.claimsType,
          typ: config.typ,
          expiryMode: config.expiryMode,
          ttlSeconds: config.ttlSeconds,
          expiresAt: config.expiresAt,
          notBeforeMode: config.notBeforeMode,
          notBeforeSeconds: config.notBeforeSeconds,
          notBeforeAt: config.notBeforeAt,
          issuedAt: config.issuedAt,
          tokenTo: config.tokenTo,
          tokenToType: config.tokenToType,
          issuer: config.issuer,
          issuerType: config.issuerType,
          subject: config.subject,
          subjectType: config.subjectType,
          audience: config.audience,
          audienceType: config.audienceType,
          jti: config.jti,
          jtiType: config.jtiType,
          kid: config.kid,
          kidType: config.kidType,
        }),
      run: (ctx) =>
        produce(ctx, { create: (claims) => new jose.SignJWT(claims), finalize: (jwt, key) => jwt.sign(key) }),
    });
  }
  RED.nodes.registerType("jose-sign", JoseSignNode);
};
