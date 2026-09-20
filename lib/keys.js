"use strict";
// Key material for jose-key: parsed once per deploy, synchronously, into a state object consumers read per message.
// PEM material becomes node:crypto KeyObjects; JWK material is handed to jose as the JWK object so jose enforces
// use, alg and key_ops; a JWK Set becomes a jose local resolver (verify only).
const crypto = require("node:crypto");
const jose = require("jose");
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
const RSA_MIN_BITS = 2048;
const MAX_MATERIAL_BYTES = 256 * 1024; // ponytail: fixed; larger pastes are mistakes, not keys
const MAX_JWKS_KEYS = 100;
const REMOTE_DEFAULTS = Object.freeze({ cacheSeconds: 600, timeoutSeconds: 5 });
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "localhost"]);
const SOURCES = Object.freeze(["secret", "pem", "jwk", "local-jwks", "remote-jwks"]);
const ENCODINGS = Object.freeze(["base64", "base64url", "hex", "utf8"]);
const PURPOSE_FAMILY = Object.freeze({
  sign: "signing",
  verify: "signing",
  encrypt: "encryption",
  decrypt: "encryption",
});
const CURVES = Object.freeze({ prime256v1: "P-256", secp384r1: "P-384", secp521r1: "P-521" }); // node:crypto -> JOSE
const PRIVATE_JWK_MEMBERS = Object.freeze(["d", "p", "q", "dp", "dq", "qi", "oth"]);

// Algorithms a key kind can serve, per family; the first entry is the `auto` choice.
const ALG_FOR = Object.freeze({
  signing: {
    oct: ["HS256", "HS384", "HS512"],
    rsa: ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
    "P-256": ["ES256"],
    "P-384": ["ES384"],
    "P-521": ["ES512"],
    Ed25519: ["Ed25519"],
  },
  encryption: {
    oct: ["dir"],
    rsa: ["RSA-OAEP-256"],
    "P-256": ["ECDH-ES+A256KW"],
    "P-384": ["ECDH-ES+A256KW"],
    "P-521": ["ECDH-ES+A256KW"],
    X25519: ["ECDH-ES+A256KW"],
  },
});
// WebCrypto usages differ between the two parts of an asymmetric key. Copies only narrow the declared set.
function partOps(family, kind) {
  if (family === "signing") return { public: ["verify"], private: ["sign"], derivePublic: ["verify"] };
  if (kind === "rsa")
    return { public: ["encrypt", "wrapKey"], private: ["decrypt", "unwrapKey"], derivePublic: ["wrapKey"] };
  return { public: [], private: ["deriveKey", "deriveBits"], derivePublic: ["deriveBits"] };
}

const ALPHABET = {
  base64: /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/,
  base64url: /^[A-Za-z0-9_-]*$/,
  hex: /^(?:[0-9a-fA-F]{2})*$/,
};

// Strict decode: alphabet and padding by regex, then decode/re-encode equality so non-canonical pad bits are rejected.
function decodeSecret(text, encoding, what = "secret") {
  if (typeof text !== "string" || text === "") throw coded("KEY_UNUSABLE", `${what} credential is empty`);
  if (!ENCODINGS.includes(encoding)) throw coded("KEY_UNUSABLE", "unknown secret encoding");
  if (encoding === "utf8") return Buffer.from(text, "utf8");
  if (!ALPHABET[encoding].test(text)) throw coded("KEY_UNUSABLE", `${what} is not valid ${encoding}`);
  const bytes = Buffer.from(text, encoding);
  const canonical = encoding === "hex" ? text.toLowerCase() : text;
  if (bytes.toString(encoding) !== canonical) throw coded("KEY_UNUSABLE", `${what} is not canonical ${encoding}`);
  if (bytes.length === 0) throw coded("KEY_UNUSABLE", `${what} credential is empty`);
  return bytes;
}

function credentialText(credentials, name) {
  const text = credentials[name] ?? "";
  if (typeof text !== "string" || text.trim() === "") throw coded("KEY_UNUSABLE", `${name} credential is empty`);
  if (Buffer.byteLength(text) > MAX_MATERIAL_BYTES) throw coded("KEY_UNUSABLE", `${name} credential is too large`);
  return text;
}

// --- secret ---------------------------------------------------------------------------------------------------
function loadSecret(config, credentials) {
  const text = credentials.secret ?? "";
  if (Buffer.byteLength(text) > MAX_MATERIAL_BYTES) throw coded("KEY_UNUSABLE", "secret credential is too large");
  const secret = decodeSecret(text, config.secretEncoding === undefined ? "base64" : config.secretEncoding);
  return { kind: "oct", secret, key: secret, bytes: secret.length };
}

// --- pem ------------------------------------------------------------------------------------------------------
function keyKind(keyObject) {
  const type = keyObject.asymmetricKeyType;
  if (type === "rsa") {
    if (keyObject.asymmetricKeyDetails.modulusLength < RSA_MIN_BITS)
      throw coded("KEY_UNUSABLE", `RSA keys need at least ${RSA_MIN_BITS} bits`);
    return "rsa";
  }
  if (type === "ec") {
    const crv = CURVES[keyObject.asymmetricKeyDetails.namedCurve];
    if (!crv) throw coded("KEY_UNUSABLE", "unsupported elliptic curve; use P-256, P-384 or P-521");
    return crv;
  }
  if (type === "ed25519") return "Ed25519";
  if (type === "x25519") return "X25519";
  throw coded("KEY_UNUSABLE", "unsupported key type");
}

const PEM_ERRORS = {
  ERR_OSSL_CRYPTO_INTERRUPTED_OR_CANCELLED: "PEM private key is encrypted; a passphrase is required",
  ERR_MISSING_PASSPHRASE: "PEM private key is encrypted; a passphrase is required",
  ERR_OSSL_BAD_DECRYPT: "PEM passphrase is wrong",
};
function loadPem(config, credentials) {
  const text = credentialText(credentials, "pem");
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) {
    let privateKey;
    try {
      const passphrase = credentials.passphrase;
      privateKey = crypto.createPrivateKey(
        typeof passphrase === "string" && passphrase !== "" ? { key: text, passphrase } : { key: text },
      );
    } catch (err) {
      throw coded("KEY_UNUSABLE", PEM_ERRORS[err?.code] ?? "PEM private key could not be parsed");
    }
    const publicKey = crypto.createPublicKey(privateKey);
    return { kind: keyKind(publicKey), private: privateKey, public: publicKey };
  }
  let publicKey;
  try {
    publicKey = crypto.createPublicKey(text); // SPKI, PKCS#1 public, or an X.509 certificate (key extraction only)
  } catch {
    throw coded("KEY_UNUSABLE", "PEM public key or certificate could not be parsed");
  }
  return { kind: keyKind(publicKey), public: publicKey };
}

// --- jwk ------------------------------------------------------------------------------------------------------
function parseJson(text, what) {
  try {
    const value = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error();
    return value;
  } catch {
    throw coded("KEY_UNUSABLE", `${what} is not a JSON object`);
  }
}

function checkJwkMetadata(jwk, family) {
  if (jwk.use !== undefined && jwk.use !== (family === "signing" ? "sig" : "enc"))
    throw coded("KEY_UNUSABLE", "JWK use does not fit the configured family");
  if (
    jwk.key_ops !== undefined &&
    (!Array.isArray(jwk.key_ops) ||
      jwk.key_ops.some((o) => typeof o !== "string") ||
      new Set(jwk.key_ops).size !== jwk.key_ops.length)
  )
    throw coded("KEY_UNUSABLE", "JWK key_ops must be an array of unique strings");
}

function jwkKind(jwk, family) {
  checkJwkMetadata(jwk, family);
  if (!["RSA", "EC", "OKP"].includes(jwk.kty)) throw coded("KEY_UNUSABLE", "unsupported JWK key type");
  if (jwk.kty === "EC" && !["P-256", "P-384", "P-521"].includes(jwk.crv))
    throw coded("KEY_UNUSABLE", "unsupported elliptic curve; use P-256, P-384 or P-521");
  if (jwk.kty === "OKP" && !["Ed25519", "X25519"].includes(jwk.crv))
    throw coded("KEY_UNUSABLE", "unsupported OKP curve; use Ed25519 or X25519");
  // Validate actual key material once, but retain JWK objects for jose's metadata checks and import cache.
  // Native modulusLength counts significant bits, unlike the encoded modulus byte length.
  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: "jwk" });
    if (jwk.d !== undefined) crypto.createPrivateKey({ key: jwk, format: "jwk" });
  } catch {
    throw coded("KEY_UNUSABLE", "asymmetric JWK material could not be parsed");
  }
  return keyKind(publicKey);
}

function loadJwk(config, credentials, family) {
  const jwk = parseJson(credentialText(credentials, "jwk"), "JWK");
  if (Array.isArray(jwk.keys)) throw coded("KEY_UNUSABLE", "this is a JSON Web Key Set; use the local-jwks source");
  if (typeof jwk.kty !== "string") throw coded("KEY_UNUSABLE", "JWK has no kty");
  const kid = typeof jwk.kid === "string" ? jwk.kid : undefined;
  const declared = jwk.alg === undefined ? undefined : jwk.alg;
  if (declared !== undefined && typeof declared !== "string") throw coded("KEY_UNUSABLE", "JWK alg must be a string");
  if (jwk.kty === "oct") {
    checkJwkMetadata(jwk, family);
    const secret = decodeSecret(jwk.k, "base64url", "JWK k");
    return { kind: "oct", secret, key: jwk, bytes: secret.length, kid, declared };
  }
  const kind = jwkKind(jwk, family);
  const isPrivate = PRIVATE_JWK_MEMBERS.some((m) => jwk[m] !== undefined);
  if (!isPrivate) return { kind, public: jwk, kid, declared };
  const ops = partOps(family, kind);
  let publicJwk;
  if (jwk.key_ops === undefined || jwk.key_ops.some((op) => ops.derivePublic.includes(op))) {
    publicJwk = Object.fromEntries(Object.entries(jwk).filter(([m]) => !PRIVATE_JWK_MEMBERS.includes(m)));
    if (jwk.key_ops !== undefined) publicJwk.key_ops = jwk.key_ops.filter((op) => ops.public.includes(op));
  }
  const privateJwk =
    jwk.key_ops === undefined
      ? jwk
      : {
          ...jwk,
          key_ops: jwk.key_ops.filter((op) => ops.private.includes(op)),
        };
  return { kind, private: privateJwk, public: publicJwk, kid, declared };
}

// --- local-jwks -------------------------------------------------------------------------------------------------
function parseAlgorithms(text) {
  if (text === undefined) text = "";
  if (typeof text !== "string") throw coded("KEY_UNUSABLE", "algorithms must be a comma-separated list");
  const list = [
    ...new Set(
      text
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    ),
  ];
  if (!list.length) throw coded("KEY_UNUSABLE", "a JSON Web Key Set needs an explicit algorithm list");
  for (const alg of list)
    if (!SIGNING_ALGS.includes(alg) || alg.startsWith("HS"))
      throw coded("KEY_UNUSABLE", "the algorithm list may only contain asymmetric JWS algorithms");
  return list;
}

function loadLocalJwks(config, credentials, family) {
  if (family !== "signing") throw coded("KEY_UNUSABLE", "a JSON Web Key Set can only verify signatures");
  const set = parseJson(credentialText(credentials, "jwk"), "JWK Set");
  if (!Array.isArray(set.keys) || set.keys.length === 0) throw coded("KEY_UNUSABLE", "JWK Set has no keys");
  if (set.keys.length > MAX_JWKS_KEYS) throw coded("KEY_UNUSABLE", `JWK Set has more than ${MAX_JWKS_KEYS} keys`);
  const algorithms = parseAlgorithms(config.algorithms);
  for (const jwk of set.keys) {
    if (jwk === null || typeof jwk !== "object" || Array.isArray(jwk))
      throw coded("KEY_UNUSABLE", "JWK Set member is not an object");
    if (jwk.kty === "oct") throw coded("KEY_UNUSABLE", "JWK Set members must be public asymmetric keys");
    if (PRIVATE_JWK_MEMBERS.some((m) => jwk[m] !== undefined))
      throw coded("KEY_UNUSABLE", "JWK Set members must not contain private material");
    const kind = jwkKind(jwk, family);
    const candidates = ALG_FOR.signing[kind];
    if (!candidates) throw coded("KEY_UNUSABLE", "JWK Set member cannot verify signatures");
    if (jwk.alg !== undefined) {
      if (!candidates.includes(jwk.alg) || !algorithms.includes(jwk.alg))
        throw coded("KEY_UNUSABLE", "a JWK Set member declares an algorithm outside the configured list");
    } else if (algorithms.length > 1) {
      throw coded("KEY_UNUSABLE", "with several algorithms every JWK Set member must declare its alg");
    } else if (!candidates.includes(algorithms[0])) {
      throw coded("KEY_UNUSABLE", "a JWK Set member does not fit the configured algorithm");
    }
  }
  return { kind: "jwks", resolver: jose.createLocalJWKSet({ keys: set.keys }), algorithms };
}

// --- remote-jwks ------------------------------------------------------------------------------------------------
function intSetting(value, name, min, max, fallback) {
  if (value === undefined) value = fallback;
  const n = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min || n > max)
    throw coded("KEY_UNUSABLE", `${name} must be an integer from ${min} to ${max}`);
  return n;
}

function parseJwksUrl(text, allowInsecureLoopback) {
  if (typeof text !== "string" || text.trim() === "") throw coded("KEY_UNUSABLE", "JWKS URL is empty");
  let url;
  try {
    url = new URL(text.trim());
  } catch {
    throw coded("KEY_UNUSABLE", "JWKS URL is not a valid URL");
  }
  if (url.username || url.password) throw coded("KEY_UNUSABLE", "JWKS URL must not contain credentials");
  if (url.hash) throw coded("KEY_UNUSABLE", "JWKS URL must not contain a fragment");
  if (url.protocol === "https:") return { url, insecure: false };
  if (url.protocol === "http:" && allowInsecureLoopback === true && LOOPBACK_HOSTS.has(url.hostname))
    return { url, insecure: true };
  throw coded(
    "KEY_UNUSABLE",
    "JWKS URL must use https (plain http is allowed on loopback only when explicitly enabled)",
  );
}

// Keep fetch failures separate from key-import failures. Forward jose's request policy unchanged.
function remoteFetch(requireAlg) {
  return async (url, options) => {
    let response;
    try {
      response = await fetch(url, options);
    } catch (err) {
      if (err?.name === "TimeoutError") throw err; // jose maps its AbortSignal timeout to ERR_JWKS_TIMEOUT
      throw coded("JWKS_FETCH");
    }
    if (requireAlg && response.status === 200) {
      const json = response.json.bind(response);
      // Parse once and let jose own/cache the filtered snapshot. Preserve malformed sets for its validation.
      response.json = async () => {
        const set = await json();
        if (set && Array.isArray(set.keys))
          set.keys = set.keys.filter(
            (key) => key === null || typeof key !== "object" || Array.isArray(key) || key.alg !== undefined,
          );
        return set;
      };
    }
    return response;
  };
}

// jose's resolver: transport failures, non-200 responses and unparsable bodies become JWKS_FETCH; a malformed
// member becomes ERR_JWKS_INVALID; jose's own JWKS codes (timeout, invalid set, no or several matching keys) pass.
function wrapRemote(remote) {
  return async (protectedHeader, token) => {
    try {
      return await remote(protectedHeader, token);
    } catch (err) {
      if (err instanceof jose.errors.JOSEError) {
        if (err.code === "ERR_JOSE_GENERIC") throw coded("JWKS_FETCH");
        throw err;
      }
      if (err?.code === "JWKS_FETCH") throw coded("JWKS_FETCH");
      throw coded("ERR_JWKS_INVALID");
    }
  };
}

function loadRemoteJwks(config, family) {
  if (family !== "signing") throw coded("KEY_UNUSABLE", "a JSON Web Key Set can only verify signatures");
  const allow = config.allowInsecureLoopback === undefined ? false : config.allowInsecureLoopback;
  if (typeof allow !== "boolean") throw coded("KEY_UNUSABLE", "allowInsecureLoopback must be true or false");
  const { url, insecure } = parseJwksUrl(config.url, allow);
  const cacheSeconds = intSetting(config.cacheSeconds, "cacheSeconds", 1, 3600, REMOTE_DEFAULTS.cacheSeconds);
  const timeoutSeconds = intSetting(config.timeoutSeconds, "timeoutSeconds", 1, 30, REMOTE_DEFAULTS.timeoutSeconds);
  const algorithms = parseAlgorithms(config.algorithms);
  const remote = jose.createRemoteJWKSet(url, {
    timeoutDuration: timeoutSeconds * 1000,
    cacheMaxAge: cacheSeconds * 1000,
    [jose.customFetch]: remoteFetch(algorithms.length > 1),
  });
  return {
    kind: "jwks",
    resolver: wrapRemote(remote),
    algorithms,
    warning: insecure ? "JWKS URL uses plain http on loopback; acceptable for local testing only" : undefined,
  };
}

// --- algorithm binding ------------------------------------------------------------------------------------------
function resolveAlg(family, requested, material) {
  const list = family === "signing" ? SIGNING_ALGS : ENCRYPTION_ALGS;
  if (requested !== "auto" && !list.includes(requested))
    throw coded("KEY_UNUSABLE", `algorithm is not supported for ${family}`);
  const candidates = ALG_FOR[family][material.kind];
  if (!candidates) throw coded("KEY_UNUSABLE", `${material.kind} keys cannot be used for ${family}`);
  // A JWK's own alg is authoritative; for direct encryption it names the content encryption (A256GCM), not "dir".
  let declared = material.declared;
  if (material.kind === "oct" && family === "encryption" && declared !== undefined) {
    if (declared !== ENC) throw coded("KEY_UNUSABLE", `for direct encryption the JWK alg must be ${ENC}`);
    declared = "dir";
  }
  if (declared !== undefined && !candidates.includes(declared))
    throw coded("KEY_UNUSABLE", "the JWK alg does not fit this key or family");
  const alg = requested === "auto" ? (declared ?? candidates[0]) : requested;
  if (!candidates.includes(alg)) throw coded("KEY_UNUSABLE", `${alg} cannot be used with this key`);
  if (declared !== undefined && declared !== alg)
    throw coded("KEY_UNUSABLE", "the configured algorithm differs from the JWK alg");
  if (material.kind === "oct") {
    if (family === "signing" && material.bytes < HMAC_MIN_BYTES[alg])
      throw coded("KEY_UNUSABLE", `${alg} needs a secret of at least ${HMAC_MIN_BYTES[alg]} bytes`);
    if (family === "encryption" && material.bytes !== DIR_BYTES)
      throw coded("KEY_UNUSABLE", `dir with ${ENC} needs a secret of exactly ${DIR_BYTES} bytes`);
  }
  return alg;
}

// Returns { ok: true, family, alg, algorithms, enc?, kid?, keys } or { ok: false, error } (KEY_UNUSABLE). Never throws.
function loadMaterial(config, credentials = {}) {
  try {
    const family = config.family === undefined ? "signing" : config.family;
    if (!["signing", "encryption"].includes(family)) throw coded("KEY_UNUSABLE", "unknown key family");
    const source = config.source === undefined ? "secret" : config.source;
    if (!SOURCES.includes(source)) throw coded("KEY_UNUSABLE", "unknown key source");
    const requested = config.alg === undefined ? "auto" : config.alg;
    let material;
    if (source === "secret") material = loadSecret(config, credentials);
    else if (source === "pem") material = loadPem(config, credentials);
    else if (source === "jwk") material = loadJwk(config, credentials, family);
    else if (source === "local-jwks") material = loadLocalJwks(config, credentials, family);
    else material = loadRemoteJwks(config, family);
    const enc = family === "encryption" ? ENC : undefined;
    if (material.kind === "jwks")
      return {
        ok: true,
        family,
        alg: material.algorithms[0],
        algorithms: material.algorithms,
        enc,
        kid: undefined,
        keys: material,
        warning: material.warning,
      };
    const alg = resolveAlg(family, requested, material);
    return { ok: true, family, alg, algorithms: [alg], enc, kid: material.kid, keys: material };
  } catch (error) {
    return {
      ok: false,
      error: error.code === "KEY_UNUSABLE" ? error : coded("KEY_UNUSABLE", "key material could not be parsed"),
    };
  }
}

// The jose key input for one purpose. Throws KEY_UNUSABLE when the state, family or key part does not fit.
function keyFor(state, purpose) {
  if (!state?.ok) throw state?.error ?? coded("KEY_UNUSABLE");
  const family = PURPOSE_FAMILY[purpose];
  if (!family) throw coded("KEY_UNUSABLE", "unknown purpose");
  if (family !== state.family) throw coded("KEY_UNUSABLE", `key is configured for ${state.family}, not ${purpose}`);
  const k = state.keys;
  if (k.kind === "oct") return k.key;
  if (k.kind === "jwks") {
    if (purpose !== "verify") throw coded("KEY_UNUSABLE", "a JSON Web Key Set can only verify signatures");
    return k.resolver;
  }
  if (purpose === "sign" || purpose === "decrypt") {
    if (!k.private) throw coded("KEY_UNUSABLE", `${purpose} needs a private key; this key has only a public part`);
    return k.private;
  }
  if (!k.public) throw coded("KEY_UNUSABLE", `the JWK key_ops do not permit ${purpose}`);
  return k.public;
}

module.exports = {
  SIGNING_ALGS,
  ENCRYPTION_ALGS,
  ENC,
  HMAC_MIN_BYTES,
  SOURCES,
  ENCODINGS,
  MAX_MATERIAL_BYTES,
  MAX_JWKS_KEYS,
  REMOTE_DEFAULTS,
  decodeSecret,
  loadMaterial,
  keyFor,
};
