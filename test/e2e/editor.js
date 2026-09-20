"use strict";
// Editor helpers: readiness by real state, programmatic dialog opening (no canvas double-click race),
// tray animation settled, config-node tray ids, overflow measurement, both themes.
const { expect } = require("@playwright/test");

const THEMES = ["light", "dark"];
const VIEWPORTS = [
  { name: "wide", width: 1440, height: 900 },
  { name: "narrow", width: 800, height: 600 },
];

const settled = (page) =>
  page.waitForFunction(() =>
    [...document.querySelectorAll(".red-ui-tray")].every((t) =>
      t.getAnimations({ subtree: true }).every((a) => a.playState !== "running"),
    ),
  );

async function gotoEditor(page, nr, theme = "light") {
  await page.addInitScript(
    ({ theme, token }) => {
      localStorage.setItem("view-dark-theme", theme);
      localStorage.setItem("auth-tokens", JSON.stringify({ access_token: token }));
    },
    { theme, token: nr.adminToken },
  );
  await page.goto(nr.base + "/");
  await page.waitForFunction(
    () =>
      window.RED?.workspaces?.active() &&
      getComputedStyle(document.querySelector("#red-ui-loading-progress")).display === "none",
  );
}
async function openNode(page, id) {
  await page.evaluate((id) => RED.editor.edit(RED.nodes.node(id)), id);
  await expect(page.locator("#node-dialog-ok")).toBeVisible();
  await settled(page);
}
async function openConfig(page, type, id = "_ADD_") {
  await page.evaluate(([t, i]) => RED.editor.editConfig("", t, i), [type, id]);
  await expect(page.locator("#node-config-dialog-ok")).toBeVisible();
  await settled(page);
}
async function closeDialog(page, { save = true, config = false } = {}) {
  const sel = `#node-${config ? "config-" : ""}dialog-${save ? "ok" : "cancel"}`;
  await expect(async () => {
    // the editor can swallow a click during a redraw; retry the whole gesture
    if ((await page.locator(sel).count()) === 0) return;
    await page.locator(sel).click({ timeout: 2000 });
    await page.waitForSelector(sel, { state: "detached", timeout: 2000 });
  }).toPass({ timeout: 20_000 });
}
async function assertNoOverflow(page) {
  const over = await page.evaluate(
    () =>
      document.querySelector(".red-ui-tray-body").scrollWidth -
      document.querySelector(".red-ui-tray-body-wrapper").clientWidth,
  );
  expect(over, `tray overflows by ${over}px`).toBeLessThanOrEqual(20);
}
module.exports = { THEMES, VIEWPORTS, gotoEditor, openNode, openConfig, closeDialog, assertNoOverflow, settled };
