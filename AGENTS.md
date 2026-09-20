# Agent guide

Design, contracts and milestones live in `PLAN.md` and `planning/` (untracked, never packed). Read `PLAN.md` first, then the CONTRACT section owning the surface you touch. Runtime/editor type names, persisted fields, message shapes and error codes are public contracts.

## Commands

- `npm run check` — package sanity, editor contract, async-style gates
- `npm test` — checks, package contract and real-runtime tests (Node-RED child process)
- `npm run test:runtime` — runtime tier only; the remote JWKS file needs `openssl` on the PATH to mint a throwaway TLS certificate (`apk add openssl` in the `node:24.0-alpine` floor container)
- `npm run test:e2e` — Playwright against the real editor; look at `test/e2e/screenshots/`
- `npm run lint && npm run format:check`
- `npm run bench` — throughput and burst measurements against a real Node-RED; prints a table for README, not a gate
- `npm run check:install` — packs the tarball and installs it into a clean Node-RED 5 on `node:24-alpine` in Docker, then round-trips example 01
- `npm run check:release` — publication metadata sanity; does not publish. Publishing itself follows `docs/RELEASE.md` and is the maintainer's action

## Rules

- Node-RED >= 5 on Node.js >= 24; no compatibility code for older versions.
- `async`/`await` only; no `.then` chains or `new Promise` in runtime or test code.
- Secrets only in credentials; never in `defaults`, examples, logs or tests committed to git.
- Each input settles exactly once via `done()`; errors are new sanitized `Error`s with an allowlisted `code`.
- Commit only when the maintainer asks. Never publish.
