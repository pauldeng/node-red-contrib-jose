# @pauldeng/node-red-contrib-jose

Node-RED nodes to sign, verify, encrypt and decrypt JSON Web Tokens, built on [jose](https://github.com/panva/jose).

**Status: pre-release.** All four operation nodes work with shared secrets: `jose-sign` and `jose-verify` (HS256, HS384, HS512), `jose-encrypt` and `jose-decrypt` (`dir` with `A256GCM`). PEM and JWK keys and remote JWK Sets are still to come; see `CHANGELOG.md`.

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

Each key configuration serves one family, signing or encryption, and one algorithm. `auto` derives the algorithm from the material: a shared secret gives `HS256` for signing and `dir` with `A256GCM` for encryption, where the secret must be exactly 32 bytes. Secrets are decoded strictly in the selected encoding and must be at least 32 bytes for `HS256`, 48 for `HS384` and 64 for `HS512`. A token whose header names any other algorithm is rejected with `ERR_JOSE_ALG_NOT_ALLOWED`; the header never chooses the key or algorithm. A credential may be a whole-value environment reference such as `${JWT_SECRET}`.

## Time claims

`jose-sign` and `jose-encrypt` set `exp` in one of four modes: expires after a number of seconds (default 3600), expires at an absolute Unix time, keep the `exp` already present in the claims, or omit it. `nbf` has the same modes and is kept by default. `iat` is set to now unless disabled. `jose-verify` and `jose-decrypt` require `exp` by default; clear _Required_ to accept tokens without one.

Both consumer nodes accept an optional _Audience_ list. A configured list requires the token’s `aud` claim to match at least one listed recipient. Blank disables audience checking; the setting is static and cannot be overridden by a message.

## Errors

Every failure is a fresh error with a stable `code` and a package-owned message. Configuration and key problems always throw to a Catch node. Token rejections either throw or, when _On rejection_ is set to the second output, leave `jose-verify` or `jose-decrypt` on the _rejected_ port with `msg.error` set. Original error text, token contents and decrypted claims are never attached. Codes are listed in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Security notes

- Signing proves the issuer, not the caller's authority; encryption alone does not authenticate the sender; verification is not authorisation.
- Stored key material is not returned to the editor; password-type credentials show a placeholder. Newly pasted material is visible in the PEM/JWK textareas until saved.
- Bound inbound rates and HTTP body sizes upstream. Choose an explicit bounded queue or drop policy; a Delay node that queues indefinitely does not bound memory. The jose nodes do not cap in-flight messages.

## Development

See `AGENTS.md` for the commands and rules. `npm test` runs the checkers, unit tests and real-runtime tests; `npm run test:e2e` drives the editor with Playwright.

## License

MIT
