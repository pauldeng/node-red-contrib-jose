"use strict";
const { values } = require("../helpers/credentials");

// Test-only consumer. Report exact fixture matches, never credential values, lengths or hashes.
module.exports = function (RED) {
  function CredentialProbe(config) {
    RED.nodes.createNode(this, config);
    this.on("input", (msg, send, done) => {
      try {
        const credentials = RED.nodes.getNode(config.key).credentials;
        msg.payload = Object.fromEntries(
          Object.entries(values).map(([key, fixtures]) => [key, fixtures.indexOf(credentials[key] ?? "")]),
        );
        send(msg);
        done();
      } catch (error) {
        done(error);
      }
    });
  }
  RED.nodes.registerType("test-credential-probe", CredentialProbe);
};
