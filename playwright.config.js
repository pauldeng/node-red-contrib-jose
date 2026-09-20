"use strict";
const { defineConfig, devices } = require("@playwright/test");
module.exports = defineConfig({
  testDir: "test/e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: "list",
  use: { trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  // No webServer and no fixed port: each spec starts its own Node-RED through test/e2e/fixtures.js.
});
