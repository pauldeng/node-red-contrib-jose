# @pauldeng/node-red-contrib-jose

Node-RED nodes to sign, verify, encrypt and decrypt JSON Web Tokens, built on [jose](https://github.com/panva/jose).

All four operation nodes work with shared secrets, PEM keys and certificates, JSON Web Keys, pasted JSON Web Key Sets and remote JSON Web Key Set URLs. See [CHANGELOG.md](CHANGELOG.md) for the release history.

Requires the Node-RED and Node.js versions declared in `package.json`.

## Nodes

| Node                       | Purpose                                                                                                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `jose-key` (configuration) | Holds key material for signing or encryption and binds the permitted algorithm policy. Material is stored in Node-RED credentials, never in the flow export. |
| `jose-sign`                | Turns a plain claims object into a compact signed JWT.                                                                                                       |
| `jose-verify`              | Verifies a compact JWT with the key's algorithm and outputs the claims, or rejects it.                                                                       |
| `jose-encrypt`             | Encrypts a plain claims object into a compact JWE.                                                                                                           |
| `jose-decrypt`             | Decrypts a compact JWE with the key's algorithm, validates the claims and outputs them, or rejects it.                                                       |

## Quick start

Install `@pauldeng/node-red-contrib-jose` through **Manage palette → Install**, or run `npm install @pauldeng/node-red-contrib-jose` in your Node-RED user directory and restart Node-RED.

1. Import the example `01-sign-and-verify-hs256` (or `02-encrypt-and-decrypt`) from the Node-RED import menu.
2. Create a secret: `openssl rand -base64 32`.
3. Open the example’s key configuration (_demo HS256 secret_ or _demo A256GCM secret_), paste the secret, deploy, and press the inject button.

The first debug node shows the token, the second the verified claims with `iat` and `exp`. Example 04 publishes a JSON Web Key Set from Node-RED and verifies against it over the loopback URL; example 05 protects an HTTP endpoint with bearer tokens and answers `401` to anything invalid.

## Keys and algorithms

| Source           | Material                                                                                  | Signing                                                       | Encryption                                          |
| ---------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| Shared secret    | base64 (default), base64url, hex or utf8 text                                             | `HS256` `HS384` `HS512`                                       | `dir` with `A256GCM` (32 bytes)                     |
| PEM              | private key (PKCS#8, PKCS#1, SEC1, optionally encrypted), public key or X.509 certificate | `RS*` `PS*` (RSA), `ES256/384/512` (P-256/384/521), `Ed25519` | `RSA-OAEP-256`, `ECDH-ES+A256KW` (P-curves, X25519) |
| JSON Web Key     | one JWK; `alg`, `use` and `key_ops` are enforced                                          | as above, plus `oct`                                          | as above, plus `oct`                                |
| JSON Web Key Set | pasted public set or remote HTTPS URL plus an explicit algorithm list                     | verify only                                                   | not applicable                                      |

Each key configuration serves one family, signing or encryption. Single-key sources bind one algorithm; JWKS sources require an explicit asymmetric algorithm allowlist. `auto` derives the algorithm from the material: a shared secret gives `HS256` for signing and `dir` with `A256GCM` for encryption, where the secret must be exactly 32 bytes; an RSA key gives `RS256` or `RSA-OAEP-256`, a P-256 key `ES256` or `ECDH-ES+A256KW`, and so on. A private key serves both directions of its family, so one configuration can sign and verify. Secrets are decoded strictly in the selected encoding and must be at least 32 bytes for `HS256`, 48 for `HS384` and 64 for `HS512`. A token outside the configured algorithm policy is rejected with `ERR_JOSE_ALG_NOT_ALLOWED`. For JWKS, token headers select eligible keys within the configured set; they cannot change the trusted set, URL or algorithm policy. A credential may be a whole-value environment reference such as `${JWT_SECRET}`.

For a private JWK, permitted operations are narrowed to each key part before use; restrictions are never expanded. For RSA-OAEP with `key_ops`, jose requires `encrypt` plus `wrapKey` to encrypt and `decrypt` plus `unwrapKey` to decrypt. An ECDH private JWK with `deriveBits` can serve both directions; its derived public key has no WebCrypto usages.

Remote JWKS keys without an `alg` declaration are eligible only when exactly one algorithm is configured. Unknown key IDs respect jose’s 30-second fetch cooldown.

## Time claims

`jose-sign` and `jose-encrypt` set `exp` in one of four modes: expires after a number of seconds (default 3600), expires at an absolute Unix time, keep the `exp` already present in the claims, or omit it. `nbf` has the same modes and is kept by default. `iat` is set to now unless disabled. `jose-verify` and `jose-decrypt` require `exp` by default; clear _Required_ to accept tokens without one.

`jose-sign` and `jose-encrypt` can also set `iss`, `sub`, `aud` and `jti` (including a random UUID) and the `kid` header. Both consumer nodes accept an optional _Issuer_ list, _Subject_, clock _Tolerance_ (up to 300 seconds) and _Max age_ (positive whole seconds), and can store the protected header in another message property. Both consumer nodes accept an optional _Audience_ list. A configured list requires the token’s `aud` claim to match at least one listed recipient. Subject matching is exact, including whitespace. Blank disables audience checking; the setting is static and cannot be overridden by a message.

## Errors

Every failure is a fresh error with a stable `code` and a package-owned message. Configuration and key problems always throw to a Catch node. Token rejections either throw or, when _On rejection_ is set to the second output, leave `jose-verify` or `jose-decrypt` on the _rejected_ port with `msg.error` set. Original error text, token contents and decrypted claims are never attached to errors. Claims and header output paths must be separate, including when different message properties refer to the same object; invalid destinations fail before either output is written. Output paths may start with `msg.`: `msg.result` and `result` name the same destination. Codes are listed in [the troubleshooting guide](https://github.com/pauldeng/node-red-contrib-jose/blob/main/docs/TROUBLESHOOTING.md).

## Security notes

- A valid signature proves possession of signing material; HMAC verifiers can also sign. Configure expected issuer and audience when identity matters. Encryption alone does not authenticate the sender, and verification is not authorisation.
- Stored key material is not returned to the editor; password-type credentials show a placeholder. Newly pasted material is visible in the PEM/JWK textareas until saved.
- A remote JSON Web Key Set is fetched over `https` only; the loopback `http` opt-in exists for local testing and warns at deploy. Keys stay cached for the configured time, so revoking a key at the issuer is not immediate. Change the key configuration or use a full deploy to create a fresh cache; redeploying only a consumer keeps it. Responses have no package-enforced byte or key-count cap; a timeout does not bound memory use.
- Bound inbound rates and HTTP body sizes upstream. Choose an explicit bounded queue or drop policy; a Delay node that queues indefinitely does not bound memory. The jose nodes do not cap in-flight messages.

## Performance

Measured with `npm run bench` on an AMD Ryzen 7 5700X3D (6 CPUs available), Node.js 26.8.1, jose 6.2.12 and Node-RED 5.0.7. Each sign/verify scenario uses 1000 inputs after one warm-up pass, with claims `{ sub: "bench", i }` (up to 23 UTF-8 bytes before time claims). Burst runs offer all 1000 messages without pacing or dropping; flow latency includes queueing from generation to the counting Function node.

| Scenario                                 |             Throughput | p50 latency | p95 latency | Child peak RSS |
| ---------------------------------------- | ---------------------: | ----------: | ----------: | -------------: |
| raw jose, sequential HS256 sign + verify |                 2280/s |     0.40 ms |     0.58 ms |              — |
| raw jose, concurrent HS256 sign + verify |                 6994/s |   132.76 ms |   137.78 ms |              — |
| raw jose, sequential RS256 sign + verify |                  979/s |     0.98 ms |     1.20 ms |              — |
| raw jose, concurrent RS256 sign + verify |                 5250/s |   180.76 ms |   182.88 ms |              — |
| flow HS256 sign -> verify                |                 4386/s |      218 ms |      223 ms |         192 MB |
| flow RS256 sign -> verify                |                 5747/s |      162 ms |      170 ms |         195 MB |
| 1000 verifies, stalled JWKS, 1 s timeout | all settled in 1050 ms |     1039 ms |     1045 ms |         198 MB |

The stalled burst produced exactly 1000 `ERR_JWKS_TIMEOUT` outcomes, zero successes and zero duplicate outcomes through one fetch. A subsequent burst through the same configuration verified all 1000 messages once the endpoint recovered; verification also succeeded after redeploy. Current child RSS was 195 MB before the burst, 198 MB at the first request, 198 MB after timeout and 200 MB after recovery. Peak RSS is the process-lifetime high-water mark, not retained bytes per message; these snapshots do not establish a leak or its absence.

These single-run measurements do not isolate node overhead or establish a throughput guarantee. Raw sequential and concurrent scheduling differ, the flow includes Node-RED message handling, and JWE performance is not measured here. Rerun on your workload and hardware; keep ingress limits and a bounded queue/drop policy upstream.

## Development

See `AGENTS.md` for the commands and rules. `npm test` runs the checkers, unit tests and real-runtime tests; `npm run test:e2e` drives the editor with Playwright; `npm run bench` prints the performance table; `npm run check:install` installs the packed tarball into a clean Node-RED 5 in Docker and round-trips example 01. Runtime TLS tests require `openssl` to generate temporary certificates; missing or failed certificate generation is a test failure, not a skip.

## License

MIT
