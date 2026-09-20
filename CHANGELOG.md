# Changelog

All notable changes to this project are documented here. Format: Keep a Changelog. Versioning: semver; breaking changes are called out under **Breaking**.

## [Unreleased]

### Added

- `jose-key` configuration node: one key per family (signing or encryption) with one bound algorithm and `auto` selection from the material. Sources: shared secret (strict canonical decoding, RFC 7518 minimum lengths), PEM private key (PKCS#8, PKCS#1, SEC1, encrypted with a passphrase), PEM public key or X.509 certificate, a single JSON Web Key (its `alg`, `use` and `key_ops` are enforced) and a pasted JSON Web Key Set with an explicit algorithm list for verification. RSA, P-256/P-384/P-521, Ed25519 and X25519 keys; `RS*`, `PS*`, `ES*`, `Ed25519`, `RSA-OAEP-256` and `ECDH-ES+A256KW`. All key material lives in password-type credentials; `${ENV}` references are honoured.
- `jose-sign`: signs a plain claims object into a compact JWT with the key's algorithm. Expiry modes (TTL, absolute, keep, omit), not-before modes, `iat`, `typ`, issuer, subject, audience and JWT ID setters (literal, message, context, environment, JSON array or random UUID), `kid` header, configurable output property.
- `jose-verify`: verifies a compact JWT against the key's algorithm only. Optional `Bearer` stripping, expected `typ`, required claims (`exp` by default), optional static issuer, audience and subject policy, clock tolerance, maximum token age, configurable claims and header output properties, and a choice between throwing to Catch or routing token rejections to a second output with `msg.error = { code, message, claim, reason }`.
- `jose-encrypt` and `jose-decrypt`: encrypted JWTs (compact JWE) with a 32-byte shared secret, `dir` key management and `A256GCM` content encryption. Same claims, time modes, `typ`, required claims, audience policy and rejection routing as the signing nodes; claims objects created in Function nodes are accepted; a failed decryption or claim check never reveals the decrypted claims.
- Stable error codes with package-owned messages, documented in `docs/TROUBLESHOOTING.md`; jose error causes and payloads are never forwarded.
- Examples `01-sign-and-verify-hs256`, `02-encrypt-and-decrypt` and `03-rs256-pem-key`.
- Package skeleton: lint/format/check gates, real Node-RED test harness, package contract test, CI matrix including the Node 24.0 floor line.

### Security

- Development tree only: Express 4.22.2 is overridden to 4.22.3 to clear transitive `qs` advisories until Node-RED updates its pin.
