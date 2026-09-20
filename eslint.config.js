"use strict";
const js = require("@eslint/js");
const globals = require("globals");
module.exports = [
  { ignores: ["node_modules/", "test-results/", "coverage/"] },
  js.configs.recommended,
  {
    files: ["**/*.js", "scripts/**/*.mjs"],
    languageOptions: { ecmaVersion: 2025, sourceType: "commonjs", globals: { ...globals.node } },
    rules: { "prefer-const": "error", "no-var": "error", "no-unused-vars": ["error", { argsIgnorePattern: "^_" }] },
  },
  {
    files: ["test/e2e/**/*.js"],
    languageOptions: { globals: { ...globals.browser, RED: "readonly" } },
    rules: { "no-empty-pattern": "off" },
  },
  { files: ["scripts/**/*.mjs"], languageOptions: { sourceType: "module" } },
];
