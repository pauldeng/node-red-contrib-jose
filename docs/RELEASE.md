# Releasing

The maintainer publishes. An agent review, dry run or passing local tests does not publish or prove registry authentication.

## Before 0.1.0

1. Make the GitHub repository public and push the reviewed source to `main`. This is a maintainer action: review the tracked history before making it public. README, troubleshooting and vulnerability-report links must work without signing in. Enable private vulnerability reporting in the repository's security settings. npm provenance requires a public source repository matching `package.json`.
2. Finish the final Codex Security scan, resolve its findings and retain its report privately. The M5 scan and its verified fixes cover the implementation at that milestone; later release changes need their own scan. `npm audit` is a separate dependency check.
3. On the exact release candidate, run `npm ci`, `npm run lint`, `npm run format:check`, `npm test`, `npm run test:e2e`, `npm audit`, `npm run check:release` and `npm run check:install`. Docker and `openssl` must be available. Inspect editor screenshots and the output of `npm pack --dry-run`. Require green hosted CI on that same commit, including Node 24.0, current 24 and 26, and the editor job.
4. Check `npm view @pauldeng/node-red-contrib-jose@0.1.0 version`. An explicit registry E404 is expected for the first release; an authentication or network failure is not evidence that the version is free. Verify that your npm account owns the `pauldeng` scope. Confirm `package.json`, its lockfile and `CHANGELOG.md` agree on `0.1.0`.
5. Commit the reviewed candidate, require a clean working tree, then create and push tag `v0.1.0` pointing to that exact commit. Recheck hosted CI after any change; never move a published tag.

## First publication (maintainer only)

From the clean, verified `v0.1.0` checkout, authenticate with `npm login` using the maintainer account and 2FA. Pack into a temporary directory, inspect the manifest and retain the resulting tarball until verification finishes:

```sh
JOSE_RELEASE_DIR=$(mktemp -d)
npm pack --pack-destination "$JOSE_RELEASE_DIR"
npm publish "$JOSE_RELEASE_DIR/pauldeng-node-red-contrib-jose-0.1.0.tgz" --dry-run --access public
# Only the maintainer executes the actual publication:
npm publish "$JOSE_RELEASE_DIR/pauldeng-node-red-contrib-jose-0.1.0.tgz" --access public
```

This bootstrap publication has no CI provenance. Do not add `--provenance` to a local publish. Do not rerun the release workflow for this already-published version.

## Trusted publishing for later versions

After the package exists, configure its npm trusted publisher with this exact tuple:

| Field             | Value                                 |
| ----------------- | ------------------------------------- |
| GitHub owner      | `pauldeng`                            |
| Repository        | `node-red-contrib-jose`               |
| Workflow filename | `release.yml`                         |
| Environment       | `release`                             |
| Allowed action    | Direct publication with `npm publish` |

Create the GitHub `release` environment with a required maintainer reviewer and restrict deployment to release tags. Require 2FA and disallow traditional publishing tokens in npm settings after trusted publishing is configured. The workflow uses OIDC and npm 11.19.0 (trusted publishing requires npm >=11.5.1); it needs no npm token secret.

For each subsequent release, update the version and lockfile, add the dated changelog entry, complete the same checks and scan the changes. Push the verified `v<version>` tag. Trigger the **Release** workflow manually on that tag, for example `gh workflow run release.yml --ref v0.1.1`, then approve its environment deployment. Branch runs and tag/version mismatches fail before publication. The workflow reruns deterministic checks, audit and a clean tarball installation; editor tests remain in CI, which must already be green for the tagged commit. Merely pushing a tag or creating a GitHub release does not publish.

## Verify the registry result

Run `npm view @pauldeng/node-red-contrib-jose@<version> dist --json`. Confirm the version, compare `dist.integrity` against the locally retained tarball for the manual bootstrap, and check provenance attestations for later CI publications. Install that exact registry version into a fresh Node-RED 5 user directory and round-trip example 01 with a newly generated secret. A workflow success message alone is insufficient. Submit the package to the Node-RED Flow Library after registry verification.

If a published version is wrong, fix it in a new version; do not retag or overwrite it.

References: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/), [npm provenance](https://docs.npmjs.com/generating-provenance-statements/), [Node-RED Flow Library submission](https://flows.nodered.org/add/node).
