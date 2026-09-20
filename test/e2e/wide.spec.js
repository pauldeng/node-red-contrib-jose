"use strict";
// Full matrix companion to dialogs.spec.js: every dialog at the wide viewport, both themes, no overflow, screenshots.
const { test, expect } = require("./fixtures");
const E = require("./editor");
const crypto = require("node:crypto");

const flow = [
  { id: "tab1", type: "tab", label: "wide" },
  {
    id: "key1",
    type: "jose-key",
    name: "k",
    family: "signing",
    source: "secret",
    alg: "auto",
    secretEncoding: "base64",
    credentials: { secret: crypto.randomBytes(32).toString("base64") },
  },
  {
    id: "key2",
    type: "jose-key",
    name: "enc",
    family: "encryption",
    source: "secret",
    alg: "auto",
    secretEncoding: "base64",
    credentials: { secret: crypto.randomBytes(32).toString("base64") },
  },
  {
    id: "sign1",
    type: "jose-sign",
    z: "tab1",
    key: "key1",
    claims: "payload",
    claimsType: "msg",
    tokenTo: "payload",
    tokenToType: "msg",
    wires: [["verify1"]],
  },
  {
    id: "verify1",
    type: "jose-verify",
    z: "tab1",
    key: "key1",
    tokenFrom: "payload",
    tokenFromType: "msg",
    claimsTo: "payload",
    claimsToType: "msg",
    wires: [[], []],
  },
  {
    id: "encrypt1",
    type: "jose-encrypt",
    z: "tab1",
    key: "key2",
    claims: "payload",
    claimsType: "msg",
    tokenTo: "payload",
    tokenToType: "msg",
    wires: [["decrypt1"]],
  },
  {
    id: "decrypt1",
    type: "jose-decrypt",
    z: "tab1",
    key: "key2",
    tokenFrom: "payload",
    tokenFromType: "msg",
    claimsTo: "payload",
    claimsToType: "msg",
    wires: [[], []],
  },
];

for (const theme of E.THEMES)
  test(`every dialog at ${E.VIEWPORTS[0].name} (${theme})`, async ({ page, nr }) => {
    await nr.deploy(flow);
    await page.setViewportSize(E.VIEWPORTS[0]);
    await E.gotoEditor(page, nr, theme);
    for (const id of ["sign1", "verify1", "encrypt1", "decrypt1"]) {
      await E.openNode(page, id);
      const flagged = await page
        .locator(".red-ui-tray-content .input-error")
        .evaluateAll((els) => els.map((e) => e.id || e.className));
      expect(flagged, `${id}: fields flagged invalid`).toEqual([]);
      // The flow omits every optional field: the dialog must show the runtime defaults, not blank controls.
      if (id.startsWith("sign") || id.startsWith("encrypt")) {
        await expect(page.locator("#node-input-expiryMode")).toHaveValue("ttl");
        await expect(page.locator("#node-input-notBeforeMode")).toHaveValue("preserve");
        await expect(page.locator("#node-input-ttlSeconds")).toHaveValue("3600");
        await expect(page.locator("#node-input-typ")).toHaveValue("JWT");
        await expect(page.locator("#node-input-issuedAt")).toBeChecked();
      } else {
        await expect(page.locator("#node-input-failureMode")).toHaveValue("catch");
        await expect(page.locator("#node-input-requiredClaims")).toHaveValue("exp");
        await expect(page.locator("#node-input-typ")).toHaveValue("JWT");
        if (id.startsWith("verify")) await expect(page.locator("#node-input-stripBearer")).toBeChecked();
        else await expect(page.locator("#node-input-stripBearer")).not.toBeChecked();
      }
      await E.assertNoOverflow(page);
      await page.screenshot({ path: `test/e2e/screenshots/${id.replace(/\d$/, "")}-${theme}-wide.png` });
      await E.closeDialog(page);
      await E.openNode(page, id);
      await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);
      await expect(page.locator("#node-input-typ")).toHaveValue("JWT");
      if (id.startsWith("sign") || id.startsWith("encrypt"))
        await expect(page.locator("#node-input-ttlSeconds")).toHaveValue("3600");
      else await expect(page.locator("#node-input-requiredClaims")).toHaveValue("exp");
      await E.closeDialog(page, { save: false });
    }
    await E.openConfig(page, "jose-key", "key1");
    await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);
    await E.assertNoOverflow(page);
    await page.screenshot({ path: `test/e2e/screenshots/key-${theme}-wide.png` });
    await E.closeDialog(page, { save: false, config: true });
  });

test("absent producer times follow runtime defaults only where defined", async ({ page, nr }) => {
  await nr.deploy(flow);
  await E.gotoEditor(page, nr);
  const rows = await page.evaluate(() => {
    const rows = [];
    for (const id of ["sign1", "encrypt1"]) {
      const node = RED.nodes.node(id);
      for (const [field, config, expected] of [
        ["ttlSeconds", { expiryMode: "ttl" }, true],
        ["notBeforeSeconds", { notBeforeMode: "offset" }, true],
        ["expiresAt", { expiryMode: "absolute" }, false],
        ["notBeforeAt", { notBeforeMode: "absolute" }, false],
        ["expiresAt", { expiryMode: "ttl" }, true],
        ["notBeforeAt", { notBeforeMode: "preserve" }, true],
      ])
        rows.push({
          id,
          field,
          expected,
          actual: node._def.defaults[field].validate.call({ ...node, ...config }, undefined),
        });
    }
    return rows;
  });
  for (const row of rows) expect(row.actual, `${row.id}: ${row.field}`).toBe(row.expected);
});

test("consumer output validators compare canonical msg paths", async ({ page, nr }) => {
  await nr.deploy(flow);
  await E.gotoEditor(page, nr);
  const rows = await page.evaluate(() =>
    ["verify1", "decrypt1"].flatMap((id) => {
      const node = RED.nodes.node(id);
      return [
        ["msg.result", "result.sub.header", false],
        ["result", "msg.result", false],
        ["msg.result", "msg.result.header", false],
        ["msg.msg.result", "msg.msg.result.header", false],
        ["msg.msg.result", "result", true],
      ].map(([claimsTo, headerTo, expected]) => ({
        id,
        claimsTo,
        headerTo,
        expected,
        actual: node._def.defaults.headerTo.validate.call({ ...node, claimsTo }, headerTo),
      }));
    }),
  );
  for (const row of rows) expect(row.actual, `${row.id}: ${row.claimsTo}/${row.headerTo}`).toBe(row.expected);
});
