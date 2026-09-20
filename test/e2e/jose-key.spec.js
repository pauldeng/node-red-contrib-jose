"use strict";
const { test, expect } = require("./fixtures");
const E = require("./editor");
const credentials = require("../helpers/credentials");

async function deployAndCapture(page, nr) {
  const after = nr.lines.length;
  // The test consumer references the config, so no unused-config confirmation is expected.
  // Wait for the response and runtime completion, not just a request being sent.
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.request().method() === "POST" && r.url().endsWith("/flows")),
    page.click("#red-ui-header-button-deploy"),
  ]);
  expect(response.ok()).toBe(true);
  await nr.waitForLog(/Started (flows|modified flows|modified nodes)/, { after });
  return response
    .request()
    .postDataJSON()
    .flows.find((n) => n.id === "key1");
}

for (const theme of E.THEMES)
  for (const property of ["pem", "jwk"])
    test(`jose-key ${property} password textarea (${theme})`, async ({ page, nr }) => {
      await nr.deploy(credentials.flow(property));
      await E.gotoEditor(page, nr, theme);
      const input = page.locator(`#node-config-input-${property}`);

      await E.openConfig(page, "jose-key", "key1");
      await expect(input).toHaveValue("__PWRD__");
      await expect(page.locator("#node-config-input-secret")).toBeHidden();
      await expect(page.locator(".red-ui-tray-content .input-error")).toHaveCount(0);
      for (const viewport of E.VIEWPORTS) {
        await page.setViewportSize({ width: viewport.width, height: viewport.height });
        await E.settled(page);
        await E.assertNoOverflow(page);
        await page.screenshot({ path: `test/e2e/screenshots/jose-key-${property}-${theme}-${viewport.name}.png` });
      }
      expect((await credentials.observe(nr))[property]).toBe(1);

      // Replacement has the same size/line count: runtime evidence must compare its actual contents.
      await input.fill(credentials.values[property][2]);
      await E.closeDialog(page, { config: true });
      let sent = await deployAndCapture(page, nr);
      expect(sent.credentials[property]).toBe(credentials.values[property][2]);
      expect((await credentials.observe(nr))[property]).toBe(2);

      // Cancel must not persist the newly typed credential.
      await E.openConfig(page, "jose-key", "key1");
      await input.fill(credentials.values[property][1]);
      await E.closeDialog(page, { config: true, save: false });

      // Saving an unrelated field preserves the stored credential and omits its value from the request.
      await E.openConfig(page, "jose-key", "key1");
      await expect(input).toHaveValue("__PWRD__");
      await page.fill("#node-config-input-name", "renamed key");
      await E.closeDialog(page, { config: true });
      sent = await deployAndCapture(page, nr);
      expect(sent.name).toBe("renamed key");
      expect(sent.credentials?.[property]).toBeUndefined();
      expect((await credentials.observe(nr))[property]).toBe(2);
      const flags = { has_secret: false, has_pem: false, has_passphrase: false, has_jwk: false };
      flags[`has_${property}`] = true;
      expect(await nr.api("GET", "/credentials/jose-key/key1")).toEqual(flags);

      const flows = JSON.stringify(await nr.api("GET", "/flows"));
      expect(flows).not.toMatch(/AAAA|BBBB|CCCC|DDDD/);
      expect(nr.lines.join("\n")).not.toMatch(/AAAA|BBBB|CCCC|DDDD|pem credential:|jose loaded with/);

      // Empty replacement explicitly clears the credential, including after a fresh editor reload.
      await E.openConfig(page, "jose-key", "key1");
      await input.fill("");
      await E.closeDialog(page, { config: true });
      await deployAndCapture(page, nr);
      expect((await credentials.observe(nr))[property]).toBe(0);
      flags[`has_${property}`] = false;
      expect(await nr.api("GET", "/credentials/jose-key/key1")).toEqual(flags);
      await E.gotoEditor(page, nr, theme);
      await E.openConfig(page, "jose-key", "key1");
      await expect(input).toHaveValue("");
    });
