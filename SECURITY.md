# Security

Report vulnerabilities privately through the [repository's security advisory form](https://github.com/pauldeng/node-red-contrib-jose/security/advisories/new), not in public issues.

What this package guarantees, and where its responsibility ends:

- Configure key material through Node-RED password credentials or whole-value environment references. Ordinary flow exports omit credential values. Node-RED and deployment administrators remain trusted: newly entered credentials are visible in their editor until saved. Package diagnostics do not include key material or token contents; failed decryptions do not attach decrypted claims. Catch and rejected messages retain their original input, so downstream Debug/log nodes can still expose input tokens or flow-supplied secrets.
- A single-key configuration binds one algorithm; a JWKS configuration binds an explicit asymmetric algorithm allowlist. Token headers select eligible keys only within that configured set. They cannot change algorithm policy, JWKS URLs or expected claims.
- Remote JSON Web Key Sets are fetched over `https` only; plain `http` is limited to loopback addresses behind an explicit opt-in that warns at deploy. Responses have no package-enforced size cap, and keys stay cached for the configured time, so revocation at the issuer is not immediate.
- A valid signature proves possession of signing material; HMAC verifiers can also sign. Bind the expected issuer and audience to the trusted key policy when identity matters. Encryption alone does not authenticate the sender, and verification is not authorisation. Flow authors and administrators control deployment policy and credentials; tokens may be hostile. No sandbox for hostile JavaScript objects supplied by trusted flow code is promised.
- Overload handling is a deployment concern: bound inbound rates and body sizes upstream. The nodes do not queue or cap in-flight messages.
- `npm audit --omit=dev` is zero before a release; development-only advisories are reviewed and, where needed, overridden in `package.json` until upstream pins move.
