# @pauldeng/node-red-contrib-jose

Node-RED nodes to sign, verify, encrypt and decrypt JSON Web Tokens, built on [jose](https://github.com/panva/jose).

**Status: pre-release.** All four operation nodes work with shared secrets, PEM keys and certificates, JSON Web Keys and pasted JSON Web Key Sets. Remote JSON Web Key Set URLs are still to come; see `CHANGELOG.md`.

Requires the Node-RED and Node.js versions declared in `package.json`.

## Nodes

| Node                       | Purpose                                                                                                                                       |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `jose-key` (configuration) | Holds one key for either signing or encryption and binds one algorithm. Material is stored in Node-RED credentials, never in the flow export. |
| `jose-sign`                | Turns a plain claims object into a compact signed JWT.                                                                                        |
| `jose-verify`              | Verifies a compact JWT with the key's algorithm and outputs the claims, or rejects it.                                                        |
| `jose-encrypt`             | Encrypts a plain claims object into a compact JWE.                                                                                            |
| `jose-decrypt`             | Decrypts a compact JWE with the key's algorithm, validates the claims and outputs them, or rejects it.                                        |

## Quick start

1. Import the example `01-sign-and-verify-hs256` (or `02-encrypt-and-decrypt`) from the Node-RED import menu.
2. Create a secret: `openssl rand -base64 32`.
3. Open the example’s key configuration (_demo HS256 secret_ or _demo A256GCM secret_), paste the secret, deploy, and press the inject button.

The first debug node shows the token, the second the verified claims with `iat` and `exp`.

## Keys and algorithms

| Source           | Material                                                                                  | Signing                                                       | Encryption                                          |
| ---------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| Shared secret    | base64 (default), base64url, hex or utf8 text                                             | `HS256` `HS384` `HS512`                                       | `dir` with `A256GCM` (32 bytes)                     |
| PEM              | private key (PKCS#8, PKCS#1, SEC1, optionally encrypted), public key or X.509 certificate | `RS*` `PS*` (RSA), `ES256/384/512` (P-256/384/521), `Ed25519` | `RSA-OAEP-256`, `ECDH-ES+A256KW` (P-curves, X25519) |
| JSON Web Key     | one JWK; `alg`, `use` and `key_ops` are enforced                                          | as above, plus `oct`                                          | as above, plus `oct`                                |
| JSON Web Key Set | pasted set of public keys plus an explicit algorithm list                                 | verify only                                                   | not applicable                                      |

Each key configuration serves one family, signing or encryption, and one algorithm. `auto` derives the algorithm from the material: a shared secret gives `HS256` for signing and `dir` with `A256GCM` for encryption, where the secret must be exactly 32 bytes; an RSA key gives `RS256` or `RSA-OAEP-256`, a P-256 key `ES256` or `ECDH-ES+A256KW`, and so on. A private key serves both directions of its family, so one configuration can sign and verify. Secrets are decoded strictly in the selected encoding and must be at least 32 bytes for `HS256`, 48 for `HS384` and 64 for `HS512`. A token whose header names any other algorithm is rejected with `ERR_JOSE_ALG_NOT_ALLOWED`; the header never chooses the key or algorithm. A credential may be a whole-value environment reference such as `${JWT_SECRET}`.

For a private JWK, permitted operations are narrowed to each key part before use; restrictions are never expanded. For RSA-OAEP with `key_ops`, jose requires `encrypt` plus `wrapKey` to encrypt and `decrypt` plus `unwrapKey` to decrypt. An ECDH private JWK with `deriveBits` can serve both directions; its derived public key has no WebCrypto usages.

## Time claims

`jose-sign` and `jose-encrypt` set `exp` in one of four modes: expires after a number of seconds (default 3600), expires at an absolute Unix time, keep the `exp` already present in the claims, or omit it. `nbf` has the same modes and is kept by default. `iat` is set to now unless disabled. `jose-verify` and `jose-decrypt` require `exp` by default; clear _Required_ to accept tokens without one.

`jose-sign` and `jose-encrypt` can also set `iss`, `sub`, `aud` and `jti` (including a random UUID) and the `kid` header. Both consumer nodes accept an optional _Issuer_ list, _Subject_, clock _Tolerance_ (up to 300 seconds) and _Max age_ (positive whole seconds), and can store the protected header in another message property. Both consumer nodes accept an optional _Audience_ list. A configured list requires the token’s `aud` claim to match at least one listed recipient. Subject matching is exact, including whitespace. Blank disables audience checking; the setting is static and cannot be overridden by a message.

## Errors

Every failure is a fresh error with a stable `code` and a package-owned message. Configuration and key problems always throw to a Catch node. Token rejections either throw or, when _On rejection_ is set to the second output, leave `jose-verify` or `jose-decrypt` on the _rejected_ port with `msg.error` set. Original error text, token contents and decrypted claims are never attached to errors. Claims and header output paths must be separate, including when different message properties refer to the same object; invalid destinations fail before either output is written. Codes are listed in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Security notes

- Signing proves the issuer, not the caller's authority; encryption alone does not authenticate the sender; verification is not authorisation.
- Stored key material is not returned to the editor; password-type credentials show a placeholder. Newly pasted material is visible in the PEM/JWK textareas until saved.
- Bound inbound rates and HTTP body sizes upstream. Choose an explicit bounded queue or drop policy; a Delay node that queues indefinitely does not bound memory. The jose nodes do not cap in-flight messages.

## Development

See `AGENTS.md` for the commands and rules. `npm test` runs the checkers, unit tests and real-runtime tests; `npm run test:e2e` drives the editor with Playwright.

## License

MIT
