#!/usr/bin/env node
// Advisory source heuristics for conventional static registrations (no browser/Node-RED).
// Not a JS parser: warnings need inspection; execution tests prove property behavior.
// Catches the drift class that recurred in every real project:
//   - a `defaults` property with no `node-input-<prop>` control (dead data)
//   - a control with no `defaults` entry (never persisted)
//   - a `defaults` property the runtime never reads (a control that lies)
//   - duplicate element ids inside one .html (config + node templates in one file)
//   - literal hex colours outside the palette `color:` (breaks the dark theme)
//   - missing help block, obsolete text/x-red, Font Awesome 5 icon names
// Usage: node check-editor-contract.mjs [package-dir]      exit 1 on FAIL
import { readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname, basename } from "node:path";

const dir = resolve(process.argv[2] ?? ".");
const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
const entries = Object.values(pkg["node-red"]?.nodes ?? {});
if (!entries.length) {
  console.error("package.json has no node-red.nodes");
  process.exit(2);
}
const res = { fail: [], warn: [], pass: [] };
const F = (m) => res.fail.push(m),
  W = (m) => res.warn.push(m),
  P = (m) => res.pass.push(m);

// all runtime sources: entry files plus every .js under their folders and lib/ (nodes often delegate)
const runtimeFiles = new Set();
const addJs = (p) => {
  if (!existsSync(p)) return;
  const st = statSync(p);
  if (st.isDirectory()) {
    for (const f of readdirSync(p)) if (!f.startsWith(".") && f !== "node_modules") addJs(join(p, f));
  } else if (/\.[cm]?js$/.test(p)) runtimeFiles.add(p);
};
for (const e of entries) {
  addJs(join(dir, e));
  addJs(dirname(join(dir, e)));
}
addJs(join(dir, "lib"));
addJs(join(dir, "src"));
const runtimeSrc = [...runtimeFiles].map((f) => readFileSync(f, "utf8")).join("\n");

const stripComments = (js) => js.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
function balancedBlock(src, from) {
  // src[from] === "{" -> returns the block text
  let depth = 0,
    i = from,
    inStr = null;
  for (; i < src.length; i++) {
    const c = src[i],
      prev = src[i - 1];
    if (inStr) {
      if (c === inStr && prev !== "\\") inStr = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      inStr = c;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}" && --depth === 0) return src.slice(from, i + 1);
  }
  return src.slice(from);
}

for (const rel of entries) {
  const html = join(dir, rel).replace(/\.js$/, ".html");
  if (!existsSync(html)) {
    F(`${rel}: no paired .html`);
    continue;
  }
  const raw = readFileSync(html, "utf8");
  const name = basename(html);
  // comments removed inside <script type="text/javascript"> blocks only (help/markdown must stay intact)
  const src = raw.replace(
    /(<script[^>]*type=["']text\/javascript["'][^>]*>)([\s\S]*?)(<\/script>)/g,
    (_, a, b, c) => a + stripComments(b) + c,
  );

  // duplicate ids inside one template (only one template is in the DOM at a time)
  for (const t of src.matchAll(/data-template-name=["']([^"']+)["'][^>]*>([\s\S]*?)<\/script>/g)) {
    const ids = [...t[2].matchAll(/\bid=["']([^"']+)["']/g)].map((m) => m[1]);
    const dupes = [...new Set(ids.filter((id, i) => ids.indexOf(id) !== i))];
    dupes.length ? F(`${t[1]}: duplicate ids in template: ${dupes.join(", ")}`) : P(`${t[1]}: template ids unique`);
    const dotted = ids.find((id) => id.includes("."));
    dotted && F(`${t[1]}: id "${dotted}" contains a dot; jQuery reads #a.b as id plus class`);
  }

  // hex colours outside registerType color:
  const scriptJs = [...src.matchAll(/<script[^>]*type=["']text\/javascript["'][^>]*>([\s\S]*?)<\/script>/g)]
    .map((m) => m[1])
    .join("\n");
  const hexes = [...src.matchAll(/#[0-9a-fA-F]{3,8}\b/g)]
    .map((m) => m[0])
    .filter((h) => (!/^#[0-9a-fA-F]{3,8}$/.test(h) ? false : true));
  const paletteHex = [...scriptJs.matchAll(/\bcolor\s*:\s*["'](#[0-9a-fA-F]{3,8})["']/g)].map((m) => m[1]);
  const strayHex = hexes.filter((h) => !paletteHex.includes(h));
  strayHex.length
    ? W(
        `${name}: ${strayHex.length} literal hex colour(s) outside the palette color (use --red-ui-* variables): ${[...new Set(strayHex)].slice(0, 5).join(" ")}`,
      )
    : P(`${name}: no stray hex colours`);

  /type=["']text\/x-red["']/.test(src) &&
    W(`${name}: text/x-red is a legacy alias; use text/html (template) and text/markdown or text/html (help)`);
  /\bfa-(layer-group|circle-notch|stream|network-wired|server-alt|database-alt)\b/.test(src) &&
    W(`${name}: Font Awesome 5+ icon name; Node-RED ships FA 4.7`);
  /class="mermaid"|```mermaid/.test(src) && W(`${name}: mermaid is not rendered in node help`);

  // per registered type
  for (const m of src.matchAll(/RED\.nodes\.registerType\(\s*["'`]([^"'`]+)["'`]\s*,\s*{/g)) {
    const type = m[1];
    const def = balancedBlock(src, m.index + m[0].length - 1);
    const isConfig = /category\s*:\s*["']config["']/.test(def);
    const prefix = isConfig ? "node-config-input-" : "node-input-";
    const dm = def.match(/\bdefaults\s*:\s*{/);
    if (!dm) {
      F(`${type}: no defaults object`);
      continue;
    }
    const defaultsBlock = balancedBlock(def, dm.index + dm[0].length - 1);
    const keys = [...defaultsBlock.matchAll(/(?:^|[,{])\s*["']?([A-Za-z_$][\w$]*)["']?\s*:\s*{/gm)].map((k) => k[1]);
    const credKeys = (() => {
      const c = def.match(/\bcredentials\s*:\s*{/);
      return c
        ? [
            ...balancedBlock(def, c.index + c[0].length - 1).matchAll(
              /(?:^|[,{])\s*["']?([A-Za-z_$][\w$]*)["']?\s*:\s*{/gm,
            ),
          ].map((k) => k[1])
        : [];
    })();
    const tmplMatch = src.match(
      new RegExp(
        `data-template-name=["']${type.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["'][^>]*>([\\s\\S]*?)<\\/script>`,
      ),
    );
    const tmpl = tmplMatch ? tmplMatch[1] : "";
    tmplMatch ? P(`${type}: template present`) : F(`${type}: no data-template-name template`);
    const helpRe = new RegExp(`data-help-name=["']${type.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`);
    helpRe.test(src) ? P(`${type}: help present`) : F(`${type}: no data-help-name help block`);
    const controlIds = [
      ...tmpl.matchAll(new RegExp(`<(?:input|select|textarea)\\b[^>]*\\bid=["']${prefix}([\\w$-]+)["']`, "g")),
    ].map((c) => c[1]);
    // also ids created in oneditprepare (editable lists, typedInput type fields) and typeField references
    const dynamicIds = [...def.matchAll(new RegExp(`["'#]${prefix}([\\w$-]+)["']`, "g"))].map((c) => c[1]);
    const allControls = new Set([...controlIds, ...dynamicIds]);
    const reserved = new Set(["name", "outputs", "inputs"]);
    for (const key of keys)
      if (["id", "type", "wires", "status", "z", "x", "y"].includes(key))
        W(`${type}: defaults.${key} may collide with editor-owned state`);
    for (const k of keys) {
      if (reserved.has(k)) continue;
      if (!allControls.has(k))
        W(
          `${type}: defaults.${k} has no ${prefix}${k} control (dead data or composite widget; document if intentional)`,
        );
      const readRe = new RegExp(
        `(config|n|def|settings|options|credentials|this|node)\\s*(\\.|\\[["'])${k}\\b|\\b${k}\\s*:\\s*(config|n)\\.|\\{[^}]*\\b${k}\\b[^}]*\\}\\s*=\\s*(config|n)\\b`,
      );
      if (!readRe.test(runtimeSrc)) W(`${type}: defaults.${k} is never read by runtime code (a control that lies?)`);
    }
    for (const c of controlIds) {
      if (!keys.includes(c) && !credKeys.includes(c) && !reserved.has(c))
        W(
          `${type}: control ${prefix}${c} has no statically recognized defaults/credentials entry; check composite save handling`,
        );
    }
    const secretInDefaults = keys.find((k) => /^(password|secret|token|apiKey|passphrase)$/i.test(k));
    secretInDefaults &&
      (src.includes("allow-secret-default:") ? W : F)(
        `${type}: defaults.${secretInDefaults} looks like a secret in defaults (exported with the flow); move it to credentials or document a migration with an allow-secret-default: comment`,
      );
    keys.length ? P(`${type}: ${keys.length} defaults, ${allControls.size} controls`) : W(`${type}: empty defaults`);
    // Cross-field validators may read live controls with a saved-state fallback. Test both contexts.
  }
}

for (const l of res.pass) console.log(`PASS ${l}`);
for (const l of res.warn) console.log(`WARN ${l}`);
for (const l of res.fail) console.log(`FAIL ${l}`);
console.log(`\n${res.pass.length} pass, ${res.warn.length} warn, ${res.fail.length} fail`);
process.exit(res.fail.length ? 1 : 0);
