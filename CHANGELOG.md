# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog. Versioning: semver; breaking changes are called out under **Breaking**.

## [Unreleased]

### Added

- Package skeleton: metadata, lint/format/check gates, real Node-RED test harness, package contract test, CI.
- `jose-key` configuration node stub with password-type credentials (`secret`, `pem`, `passphrase`, `jwk`); no key material is parsed yet.

### Fixed

- Enforce the CI Node floor independently of the deferred release workflow, and require lockfile dependency parity.
- Remove credential-metadata probe logging from the shipped node; test exact PEM/JWK credential replacement, retention, cancellation and clearing through the real runtime/editor.
- Override development-only Express 4.22.2 with 4.22.3 to resolve the transitive `qs` advisories; remove the override when Node-RED updates its pin.
