"use strict";
// Loaded at module top so a Node.js version that cannot require() the ESM-only jose fails once, in the Node-RED log.
require("jose");
const { loadMaterial, keyFor } = require("../lib/keys");

module.exports = function (RED) {
  function JoseKeyNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    // Parsed once, synchronously. Consumers call keyFor per message and never cache the result.
    node.state = loadMaterial(
      {
        family: config.family,
        source: config.source,
        alg: config.alg,
        algorithms: config.algorithms,
        secretEncoding: config.secretEncoding,
        url: config.url,
        allowInsecureLoopback: config.allowInsecureLoopback,
        cacheSeconds: config.cacheSeconds,
        timeoutSeconds: config.timeoutSeconds,
      },
      node.credentials ?? {},
    );
    if (!node.state.ok)
      node.warn(node.state.error.message); // package-owned category text, once per deploy
    else if (node.state.warning) node.warn(node.state.warning);
    node.keyFor = (purpose) => keyFor(node.state, purpose);
  }
  RED.nodes.registerType("jose-key", JoseKeyNode, {
    credentials: {
      secret: { type: "password" },
      pem: { type: "password" },
      passphrase: { type: "password" },
      jwk: { type: "password" },
    },
  });
};
