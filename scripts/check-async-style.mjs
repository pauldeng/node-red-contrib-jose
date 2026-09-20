#!/usr/bin/env node
// Enforced gate for the two rules the maintainer repeated most across five packages:
//   1. runtime AND test code use async/await: no `.then/.catch/.finally` chains, no `new Promise`,
//      no `Promise.<x>` other than the concurrency combinators (all/allSettled/race/any/withResolvers)
//   2. tests wait for signals, not time: no sleeps, no setInterval polling
// Syntax is not proof of rejection handling; behavioral tests still prove settlement and cleanup.
// Usage: node check-async-style.mjs <file-or-dir>... [--allow-timers]     exit 1 on any violation
// A justified exception carries an inline comment on the same line:
//   // allow-promise: <reason>     e.g. wrapping a callback-only API, a settle guard on a shared promise
//   // allow-timer: <reason>       e.g. a bounded negative assertion, a process-boundary readiness poll
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, extname } from "node:path";

const args = process.argv.slice(2);
const allowTimers = args.includes("--allow-timers");
const paths = args.filter((a) => !a.startsWith("--"));
if (!paths.length) {
  console.error("usage: check-async-style.mjs <file-or-dir>... [--allow-timers]");
  process.exit(2);
}

const files = [];
const walk = (p) => {
  if (statSync(p).isDirectory()) {
    for (const f of readdirSync(p)) if (f !== "node_modules" && !f.startsWith(".")) walk(join(p, f));
  } else if ([".js", ".mjs", ".cjs"].includes(extname(p))) files.push(p);
};
paths.forEach(walk);

const promiseRules = [
  [
    /\bnew\s+Promise\s*\(/,
    "new Promise(): use await with events.once(), for await, util.promisify, or the library's promise API",
  ],
  [/\.then\s*\(/, ".then(): use await"],
  [/\.catch\s*\(/, ".catch(): use try/catch around await"],
  [/\.finally\s*\(/, ".finally(): use try/finally around await"],
  [
    /\bPromise\.(?!all\b|allSettled\b|race\b|any\b|withResolvers\b)\w+\s*\(/,
    "Promise.<x>(): only all/allSettled/race/any/withResolvers express concurrency",
  ],
];
const timerRules = [
  [
    /\bsetTimeout\s*\(\s*(resolve|res|r|done|cb)\b/,
    "sleep via setTimeout(resolve): wait for the event or promise that proves completion",
  ],
  [/\bsetInterval\s*\(/, "setInterval polling: subscribe to the event or use for await over an async iterator"],
  [
    /\b(sleep|delay|wait)\s*\(\s*\d[\d_]*\s*\)/,
    "fixed sleep: replace with an event wait; keep only as a bounded negative-assertion window and say why",
  ],
];
const isTest = (f) => /(^|\/)(test|tests|__tests__)\//.test(f) || /\.(test|spec)\.[cm]?js$/.test(f);
const stripStringsAndComments = (line) => line.replace(/\/\/.*$/, "").replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""');

let violations = 0;
for (const f of files) {
  readFileSync(f, "utf8")
    .split("\n")
    .forEach((raw, i) => {
      const t = raw.trim();
      if (!t || t.startsWith("//") || t.startsWith("*") || t.startsWith("/*")) return;
      const line = stripStringsAndComments(raw);
      const check = (rules, tag) => {
        for (const [re, why] of rules) {
          if (re.test(line) && !raw.includes(`allow-${tag}:`)) {
            console.log(`${f}:${i + 1}: ${why}\n    ${t.slice(0, 120)}`);
            violations++;
          }
        }
      };
      check(promiseRules, "promise");
      if (!allowTimers && isTest(f)) check(timerRules, "timer");
    });
}
console.log(`\n${files.length} files scanned, ${violations} violation(s)`);
process.exit(violations ? 1 : 0);
