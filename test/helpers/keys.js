"use strict";
// Throwaway asymmetric test material generated per process; nothing here is committed key material.
const crypto = require("node:crypto");
const jose = require("jose");

const pairs = {
  rsa: crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }),
  rsa1024: crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }),
  p256: crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }),
  p384: crypto.generateKeyPairSync("ec", { namedCurve: "P-384" }),
  p521: crypto.generateKeyPairSync("ec", { namedCurve: "P-521" }),
  ed25519: crypto.generateKeyPairSync("ed25519"),
  x25519: crypto.generateKeyPairSync("x25519"),
};
const pem = {
  pkcs8: (name) => pairs[name].privateKey.export({ type: "pkcs8", format: "pem" }),
  pkcs1: () => pairs.rsa.privateKey.export({ type: "pkcs1", format: "pem" }),
  sec1: () => pairs.p256.privateKey.export({ type: "sec1", format: "pem" }),
  spki: (name) => pairs[name].publicKey.export({ type: "spki", format: "pem" }),
  rsaPublicPkcs1: () => pairs.rsa.publicKey.export({ type: "pkcs1", format: "pem" }),
  encrypted: (name, passphrase) =>
    pairs[name].privateKey.export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase }),
};
const jwk = {
  private: async (name, extra = {}) => ({ ...(await jose.exportJWK(pairs[name].privateKey)), ...extra }),
  public: async (name, extra = {}) => ({ ...(await jose.exportJWK(pairs[name].publicKey)), ...extra }),
};
module.exports = { pairs, pem, jwk };
