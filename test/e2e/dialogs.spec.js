"use strict";
// M1 editor smoke: the three dialogs open clean, persist edits and switch conditional rows without overflow.
const { test, expect } = require("./fixtures");
const E = require("./editor");
const crypto = require("node:crypto");

const flow = [
  { id: "tab1", type: "tab", label: "dialogs" },
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
    id: "sign1",
    type: "jose-sign",
    z: "tab1",
    name: "",
    key: "key1",
    claims: "payload",
    claimsType: "msg",
    typ: "JWT",
    expiryMode: "ttl",
    ttlSeconds: 3600,
    expiresAt: "",
    issuedAt: true,
    notBeforeMode: "preserve",
    notBeforeSeconds: 0,
    notBeforeAt: "",
    tokenTo: "payload",
    tokenToType: "msg",
    wires: [["verify1"]],
  },
  {
    id: "verify1",
    type: "jose-verify",
    z: "tab1",
    name: "",
    key: "key1",
    tokenFrom: "payload",
    tokenFromType: "msg",
    stripBearer: true,
    typ: "JWT",
    requiredClaims: "exp",
    claimsTo: "payload",
    claimsToType: "msg",
    failureMode: "catch",
    wires: [[], []],
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
    id: "encrypt1",
    type: "jose-encrypt",
    z: "tab1",
    name: "",
    key: "key2",
    claims: "payload",
    claimsType: "msg",
    typ: "JWT",
    expiryMode: "ttl",
    ttlSeconds: 3600,
    expiresAt: "",
    issuedAt: true,
    notBeforeMode: "preserve",
    notBeforeSeconds: 0,
    notBeforeAt: "",
    tokenTo: "payload",
    tokenToType: "msg",
    wires: [["decrypt1"]],
  },
  {
    id: "decrypt1",
    type: "jose-decrypt",
    z: "tab1",
    name: "",
    key: "key2",
    tokenFrom: "payload",
    tokenFromType: "msg",
    stripBearer: false,
    typ: "JWT",
    requiredClaims: "exp",
    claimsTo: "payload",
    claimsToType: "msg",
    failureMode: "catch",
    wires: [[], []],
  },
];

for (const theme of E.THEMES) {
  test(`jose-sign dialog (${theme})`, async ({ page, nr }) => {
    await nr.deploy(flow);
    await page.setViewportSize(E.VIEWPORTS[1]);
    await E.gotoEditor(page, nr, theme);
    await E.openNode(page, "sign1");
    await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);
    await expect(page.locator("#node-input-ttlSeconds")).toBeVisible();
    await expect(page.locator("#node-input-expiresAt")).toBeHidden();
    await E.assertNoOverflow(page);
    await page.screenshot({ path: `test/e2e/screenshots/jose-sign-${theme}.png` });
    await page.selectOption("#node-input-expiryMode", "absolute");
    await expect(page.locator("#node-input-ttlSeconds")).toBeHidden();
    await page.fill("#node-input-expiresAt", "1700000000");
    await page.fill("#node-input-name", "edited");
    await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);
    await E.closeDialog(page);
    await E.openNode(page, "sign1");
    await expect(page.locator("#node-input-name")).toHaveValue("edited");
    await expect(page.locator("#node-input-expiryMode")).toHaveValue("absolute");
    await expect(page.locator("#node-input-expiresAt")).toHaveValue("1700000000");
    await expect(page.locator("#node-input-ttlSeconds")).toHaveValue("3600", "hidden value is kept");
    await E.closeDialog(page, { save: false });
  });

  test(`jose-verify dialog (${theme})`, async ({ page, nr }) => {
    await nr.deploy(flow);
    await page.setViewportSize(E.VIEWPORTS[1]);
    await E.gotoEditor(page, nr, theme);
    await E.openNode(page, "verify1");
    await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);
    await expect(page.locator("#node-input-stripBearer")).toBeChecked();
    await E.assertNoOverflow(page);
    await page.screenshot({ path: `test/e2e/screenshots/jose-verify-${theme}.png` });
    await page.setViewportSize(E.VIEWPORTS[0]);
    await E.settled(page);
    await E.assertNoOverflow(page);
    await page.screenshot({ path: `test/e2e/screenshots/jose-verify-${theme}-wide.png` });
    await page.setViewportSize(E.VIEWPORTS[1]);
    await E.settled(page);
    await page.selectOption("#node-input-failureMode", "output");
    await page.uncheck("#node-input-stripBearer");
    await page.fill("#node-input-requiredClaims", "exp, sub");
    await page.fill("#node-input-audience", "api, worker");
    await E.closeDialog(page);
    await E.openNode(page, "verify1");
    await expect(page.locator("#node-input-failureMode")).toHaveValue("output");
    await expect(page.locator("#node-input-stripBearer")).not.toBeChecked();
    await expect(page.locator("#node-input-requiredClaims")).toHaveValue("exp, sub");
    await expect(page.locator("#node-input-audience")).toHaveValue("api, worker");
    await E.closeDialog(page, { save: false });
  });

  test(`jose-encrypt and jose-decrypt dialogs (${theme})`, async ({ page, nr }) => {
    await nr.deploy(flow);

    await page.setViewportSize(E.VIEWPORTS[1]);

    await E.gotoEditor(page, nr, theme);

    await E.openNode(page, "encrypt1");

    await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);

    await E.assertNoOverflow(page);

    await page.screenshot({ path: `test/e2e/screenshots/jose-encrypt-${theme}.png` });

    await page.fill("#node-input-name", "enc edited");

    await E.closeDialog(page);

    await E.openNode(page, "encrypt1");

    await expect(page.locator("#node-input-name")).toHaveValue("enc edited");

    await E.closeDialog(page, { save: false });

    await E.openNode(page, "decrypt1");

    await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);

    await expect(page.locator("#node-input-stripBearer")).not.toBeChecked();

    await E.assertNoOverflow(page);

    await page.screenshot({ path: `test/e2e/screenshots/jose-decrypt-${theme}.png` });
    await page.setViewportSize(E.VIEWPORTS[0]);
    await E.settled(page);
    await E.assertNoOverflow(page);
    await page.screenshot({ path: `test/e2e/screenshots/jose-decrypt-${theme}-wide.png` });
    await page.setViewportSize(E.VIEWPORTS[1]);
    await E.settled(page);
    await page.fill("#node-input-audience", "service-a, service-b");
    await page.selectOption("#node-input-failureMode", "output");
    await E.closeDialog(page);
    await E.openNode(page, "decrypt1");
    await expect(page.locator("#node-input-audience")).toHaveValue("service-a, service-b");
    await expect(page.locator("#node-input-failureMode")).toHaveValue("output");
    await page.fill("#node-input-audience", "cancelled");
    await E.closeDialog(page, { save: false });
    await E.openNode(page, "decrypt1");
    await expect(page.locator("#node-input-audience")).toHaveValue("service-a, service-b");
    await page.fill("#node-input-audience", "");
    await E.closeDialog(page);
    await E.openNode(page, "decrypt1");
    await expect(page.locator("#node-input-audience")).toHaveValue("");
    await E.closeDialog(page, { save: false });
  });

  test(`jose-key algorithm list follows the family (${theme})`, async ({ page, nr }) => {
    await nr.deploy(flow);
    await page.setViewportSize(E.VIEWPORTS[1]);
    await E.gotoEditor(page, nr, theme);
    await E.openConfig(page, "jose-key", "key1");
    const options = () => page.locator("#node-config-input-alg option").allTextContents();
    await expect(page.locator("#node-config-input-alg")).toHaveValue("auto");
    expect(await options()).toContain("HS256");
    await page.selectOption("#node-config-input-family", "encryption");
    expect(await options()).toContain("dir");
    expect(await options()).not.toContain("HS256");
    await expect(page.locator("#node-config-input-secretEncoding")).toBeVisible();
    await page.selectOption("#node-config-input-source", "pem");
    await expect(page.locator("#node-config-input-secretEncoding")).toBeHidden();
    await expect(page.locator("#node-config-input-pem")).toBeVisible();
    await E.assertNoOverflow(page);
    await page.screenshot({ path: `test/e2e/screenshots/jose-key-${theme}.png` });
    await E.closeDialog(page, { save: false, config: true });
  });
}

test("an invalid imported key family opens without breaking the editor", async ({ page, nr }) => {
  await nr.deploy(flow.map((node) => (node.id === "key1" ? { ...node, family: "invalid" } : node)));
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await E.gotoEditor(page, nr);
  await E.openConfig(page, "jose-key", "key1");
  await expect(page.locator("#node-config-input-source")).toBeVisible();
  expect(errors).toEqual([]);
  await page.selectOption("#node-config-input-family", "signing");
  await expect(page.locator("#node-config-input-alg")).toHaveValue("auto");
  await E.closeDialog(page, { config: true });
});

test("output path validators reject exact prototype segments and allow similar names", async ({ page, nr }) => {
  await nr.deploy(flow);
  await E.gotoEditor(page, nr);
  for (const [id, property] of [
    ["sign1", "tokenTo"],
    ["verify1", "claimsTo"],
    ["encrypt1", "tokenTo"],
    ["decrypt1", "claimsTo"],
  ]) {
    await E.openNode(page, id);
    for (const [value, valid] of [
      ["__proto__.x", false],
      ["payload.__proto__", false],
      ["payload.__proto__safe", true],
    ]) {
      const result = await page.evaluate(
        ({ id, property, value }) => {
          const node = RED.nodes.node(id);
          return node._def.defaults[property].validate.call(node, value);
        },
        { id, property, value },
      );
      expect(result, `${property}: ${value}`).toBe(valid);
    }
    await E.closeDialog(page, { save: false });
  }
});
