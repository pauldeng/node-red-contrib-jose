"use strict";
const jose = require("jose");
const { attach, producerSetup, produce } = require("../lib/operation");

module.exports = function (RED) {
  function JoseEncryptNode(config) {
    RED.nodes.createNode(this, config);
    attach(RED, this, RED.nodes.getNode(config.key), {
      kind: "produce",
      purpose: "encrypt",
      family: "encryption",
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
        }),
      run: (ctx) =>
        produce(ctx, { create: (claims) => new jose.EncryptJWT(claims), finalize: (jwt, key) => jwt.encrypt(key) }),
    });
  }
  RED.nodes.registerType("jose-encrypt", JoseEncryptNode);
};
