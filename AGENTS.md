# Agent guide

Design, contracts and milestones live in `PLAN.md` and `planning/` (untracked, never packed). Read `PLAN.md` first, then the CONTRACT section owning the surface you touch. Runtime/editor type names, persisted fields, message shapes and error codes are public contracts.

## Commands

- `npm run check` — package sanity, editor contract, async-style gates
- `npm test` — checks, package contract and real-runtime tests (Node-RED child process)
- `npm run test:runtime` — runtime tier only
- `npm run test:e2e` — Playwright against the real editor; look at `test/e2e/screenshots/`
- `npm run lint && npm run format:check`
- `npm run check:release` — publication metadata sanity; does not publish

## Rules

- Node-RED >= 5 on Node.js >= 24; no compatibility code for older versions.
- `async`/`await` only; no `.then` chains or `new Promise` in runtime or test code.
- Secrets only in credentials; never in `defaults`, examples, logs or tests committed to git.
- Each input settles exactly once via `done()`; errors are new sanitized `Error`s with an allowlisted `code`.
- Commit only when the maintainer asks. Never publish.
