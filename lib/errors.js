"use strict";
// Closed error table. Every code has exactly one row in docs/TROUBLESHOOTING.md (asserted by test/unit/errors.test.js).
// Messages are package-owned: no original error text, cause, payload or input value ever leaves a node.
const { errors: joseErrors } = require("jose");
const CODES = Object.freeze({
  NO_KEY_CONFIG: "no key configuration selected",
  KEY_UNUSABLE: "key configuration cannot be used for this operation",
  INVALID_INPUT: "a configured option or evaluated input is invalid",
  INVALID_CLAIMS: "claims must be a plain JSON object",
  OUTPUT_INVALID: "output destination cannot be written",
  NODE_CLOSING: "node closed while the message was in flight",
  JWKS_FETCH: "JSON Web Key Set could not be fetched",
  INTERNAL_ERROR: "unexpected error",
  NO_TOKEN: "no usable token found",
  INPUT_TOO_LARGE: "token exceeds the size limit",
  ERR_JWT_EXPIRED: "token has expired",
  ERR_JWT_CLAIM_VALIDATION_FAILED: "a claim did not match the configured policy",
  ERR_JWT_INVALID: "token is not a valid JWT",
  ERR_JWS_INVALID: "token is not a valid compact JWS",
  ERR_JWS_SIGNATURE_VERIFICATION_FAILED: "signature verification failed",
  ERR_JWE_INVALID: "token is not a valid compact JWE",
  ERR_JWE_DECRYPTION_FAILED: "decryption failed",
  ERR_JOSE_ALG_NOT_ALLOWED: "token algorithm is not allowed by the key configuration",
  ERR_JOSE_NOT_SUPPORTED: "token uses an unsupported algorithm or feature",
  ERR_JWKS_NO_MATCHING_KEY: "no key in the JSON Web Key Set matches the token",
  ERR_JWKS_TIMEOUT: "JSON Web Key Set request timed out",
  ERR_JWKS_INVALID: "JSON Web Key Set is invalid",
  ERR_JWK_INVALID: "JSON Web Key is invalid",
  ERR_JWKS_MULTIPLE_MATCHING_KEYS: "several keys in the JSON Web Key Set match the token",
});

// Token rejections: routed to the second output when failureMode is "output"; everything else always throws.
const REJECTION_CODES = new Set([
  "NO_TOKEN",
  "INPUT_TOO_LARGE",
  "ERR_JWT_EXPIRED",
  "ERR_JWT_CLAIM_VALIDATION_FAILED",
  "ERR_JWT_INVALID",
  "ERR_JWS_INVALID",
  "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
  "ERR_JWE_INVALID",
  "ERR_JWE_DECRYPTION_FAILED",
  "ERR_JOSE_ALG_NOT_ALLOWED",
  "ERR_JOSE_NOT_SUPPORTED",
  "ERR_JWKS_NO_MATCHING_KEY",
]);

const OWN = new WeakMap();
const SAFE_ID = /^[\w-]{1,64}$/; // claim names come from a fixed vocabulary or from the node's own configuration

// Build a package-owned error. `detail` must be package text, never user or token content.
function coded(code, detail) {
  if (!Object.hasOwn(CODES, code)) throw new Error(`unknown error code ${code}`);
  const err = new Error(detail ? `${CODES[code]}: ${detail}` : CODES[code]);
  err.code = code;
  OWN.set(err, { code, message: err.message });
  return err;
}

// Stage boundaries decide routing; only actual jose errors from the crypto stage may preserve library codes.
const STAGE_CODES = { evaluate: "INVALID_INPUT", claims: "INVALID_CLAIMS", output: "OUTPUT_INVALID" };
const REASONS = new Set(["missing", "invalid", "check_failed", "unspecified"]); // jose JWTClaimValidationFailure.reason
function sanitize(err, stage = "unknown") {
  const own = OWN.get(err);
  let out;
  if (own) {
    out = coded(own.code);
    out.message = own.message;
    OWN.set(out, own);
  } else if (Object.hasOwn(STAGE_CODES, stage)) {
    out = coded(STAGE_CODES[stage]);
  } else if (stage === "jose" && err instanceof joseErrors.JOSEError) {
    out = coded(Object.hasOwn(CODES, err.code) ? err.code : "INTERNAL_ERROR");
    if (err instanceof joseErrors.JWTClaimValidationFailed || err instanceof joseErrors.JWTExpired) {
      if (typeof err.claim === "string" && SAFE_ID.test(err.claim)) out.claim = err.claim;
      if (REASONS.has(err.reason)) out.reason = err.reason;
    }
  } else if (stage === "jose" && err instanceof Error && !err.code) {
    out = coded(err.name === "DataCloneError" ? "INVALID_CLAIMS" : "INVALID_INPUT");
  } else {
    out = coded("INTERNAL_ERROR");
  }
  out.stage = stage;
  return out;
}

module.exports = { CODES, REJECTION_CODES, coded, sanitize };
