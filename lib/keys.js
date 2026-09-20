"use strict";
// Key material for jose-key: parsed once per deploy, synchronously, into a state object consumers read per message.
const { coded } = require("./errors");

const SIGNING_ALGS = Object.freeze([
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "Ed25519",
]);
const ENCRYPTION_ALGS = Object.freeze(["dir", "RSA-OAEP-256", "ECDH-ES+A256KW"]);
const ENC = "A256GCM";
const HMAC_MIN_BYTES = Object.freeze({ HS256: 32, HS384: 48, HS512: 64 }); // RFC 7518 section 3.2: at least the hash size
const DIR_BYTES = 32; // A256GCM content encryption key
const MAX_MATERIAL_BYTES = 256 * 1024; // ponytail: fixed; larger pastes are mistakes, not keys
const SOURCES = Object.freeze(["secret", "pem", "jwk", "local-jwks", "remote-jwks"]);
const ENCODINGS = Object.freeze(["base64", "base64url", "hex", "utf8"]);
const PURPOSE_FAMILY = Object.freeze({
  sign: "signing",
  verify: "signing",
  encrypt: "encryption",
  decrypt: "encryption",
});

const ALPHABET = {
  base64: /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
  base64url: /^[A-Za-z0-9_-]*$/,
  hex: /^(?:[0-9a-fA-F]{2})*$/,
};

// Strict decode: alphabet and padding by regex, then decode/re-encode equality so non-canonical pad bits are rejected.
function decodeSecret(text, encoding) {
  if (typeof text !== "string" || text === "") throw coded("KEY_UNUSABLE", "secret credential is empty");
  if (!ENCODINGS.includes(encoding)) throw coded("KEY_UNUSABLE", "unknown secret encoding");
  if (encoding === "utf8") return Buffer.from(text, "utf8");
  if (!ALPHABET[encoding].test(text)) throw coded("KEY_UNUSABLE", `secret is not valid ${encoding}`);
  const bytes = Buffer.from(text, encoding);
  const canonical = encoding === "hex" ? text.toLowerCase() : text;
  if (bytes.toString(encoding) !== canonical) throw coded("KEY_UNUSABLE", `secret is not canonical ${encoding}`);
  if (bytes.length === 0) throw coded("KEY_UNUSABLE", "secret credential is empty");
  return bytes;
}

function resolveAlg(family, requested, material) {
  const list = family === "signing" ? SIGNING_ALGS : ENCRYPTION_ALGS;
  if (requested !== "auto" && !list.includes(requested))
    throw coded("KEY_UNUSABLE", `algorithm is not supported for ${family}`);
  if (material.kind === "secret") {
    if (family === "signing") {
      const alg = requested === "auto" ? "HS256" : requested;
      if (!(alg in HMAC_MIN_BYTES))
        throw coded("KEY_UNUSABLE", "a shared secret can only sign with HS256, HS384 or HS512");
      if (material.secret.length < HMAC_MIN_BYTES[alg])
        throw coded("KEY_UNUSABLE", `${alg} needs a secret of at least ${HMAC_MIN_BYTES[alg]} bytes`);
      return alg;
    }
    const alg = requested === "auto" ? "dir" : requested;
    if (alg !== "dir") throw coded("KEY_UNUSABLE", "a shared secret can only encrypt with dir");
    if (material.secret.length !== DIR_BYTES)
      throw coded("KEY_UNUSABLE", `dir with ${ENC} needs a secret of exactly ${DIR_BYTES} bytes`);
    return alg;
  }
  throw coded("KEY_UNUSABLE", `${material.kind} source is not implemented yet`);
}

function loadSecret(config, credentials) {
  const text = credentials.secret ?? "";
  if (Buffer.byteLength(text) > MAX_MATERIAL_BYTES) throw coded("KEY_UNUSABLE", "secret credential is too large");
  return {
    kind: "secret",
    secret: decodeSecret(text, config.secretEncoding === undefined ? "base64" : config.secretEncoding),
  };
}

// Returns { ok: true, family, alg, enc?, kid?, keys } or { ok: false, error } with a KEY_UNUSABLE error. Never throws.
function loadMaterial(config, credentials = {}) {
  try {
    const family = config.family === undefined ? "signing" : config.family;
    if (!["signing", "encryption"].includes(family)) throw coded("KEY_UNUSABLE", "unknown key family");
    const source = config.source === undefined ? "secret" : config.source;
    if (!SOURCES.includes(source)) throw coded("KEY_UNUSABLE", "unknown key source");
    if (source !== "secret") throw coded("KEY_UNUSABLE", `${source} source is not implemented yet`);
    const material = loadSecret(config, credentials);
    const alg = resolveAlg(family, config.alg === undefined ? "auto" : config.alg, material);
    return { ok: true, family, alg, enc: family === "encryption" ? ENC : undefined, kid: material.kid, keys: material };
  } catch (error) {
    return {
      ok: false,
      error: error.code === "KEY_UNUSABLE" ? error : coded("KEY_UNUSABLE", "key material could not be parsed"),
    };
  }
}

// The jose key input for one purpose. Throws KEY_UNUSABLE when the state or family does not fit.
function keyFor(state, purpose) {
  if (!state?.ok) throw state?.error ?? coded("KEY_UNUSABLE");
  const family = PURPOSE_FAMILY[purpose];
  if (!family) throw coded("KEY_UNUSABLE", "unknown purpose");
  if (family !== state.family) throw coded("KEY_UNUSABLE", `key is configured for ${state.family}, not ${purpose}`);
  if (state.keys.kind === "secret") return state.keys.secret;
  throw coded("KEY_UNUSABLE", `${state.keys.kind} source is not implemented yet`);
}

module.exports = {
  SIGNING_ALGS,
  ENCRYPTION_ALGS,
  ENC,
  HMAC_MIN_BYTES,
  SOURCES,
  ENCODINGS,
  MAX_MATERIAL_BYTES,
  decodeSecret,
  loadMaterial,
  keyFor,
};
