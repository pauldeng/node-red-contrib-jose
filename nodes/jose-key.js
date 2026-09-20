"use strict";
// Loaded at module top so a Node.js version that cannot require() the ESM-only jose fails once, in the Node-RED log.
require("jose");

module.exports = function (RED) {
  function JoseKeyNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    node.family = config.family;
    node.source = config.source;
    const error = new Error("key source not implemented yet");
    error.code = "KEY_UNUSABLE";
    node.state = { ok: false, error };
    node.keyFor = () => {
      throw node.state.error;
    };
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
