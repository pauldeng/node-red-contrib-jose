"use strict";
// One isolated real Node-RED per test, started through the same harness the runtime tests use.
const base = require("@playwright/test");
const path = require("node:path");
const { startNodeRed } = require("../helpers/node-red");
const { settings } = require("../helpers/credentials");

exports.test = base.test.extend({
  nr: async ({}, use) => {
    const nr = await startNodeRed({ packageDir: path.resolve(__dirname, "../.."), settings });
    try {
      await use(nr);
    } finally {
      await nr.stop();
    }
  },
});
exports.expect = base.expect;
