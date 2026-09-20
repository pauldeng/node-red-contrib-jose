"use strict";
// Claims, time modes, token extraction, output preflight and rejection shaping shared by the four operation nodes.
const { coded } = require("./errors");

const MAX_TOKEN_BYTES = 1024 * 1024; // ponytail: fixed; compact JWTs are small and JWE payloads rarely approach this
const YEAR = 31536000;
const PATH_RE = /^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$/;
const COMPACT_RE = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*){2,4}$/;

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Buffer.isBuffer(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

// Absent config -> documented default; present but empty/null/non-integer/out of range -> INVALID_INPUT.
function intOption(value, { name, min, max, fallback }) {
  if (value === undefined) value = fallback;
  if (value === undefined) throw coded("INVALID_INPUT", `${name} is required`);
  const n = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < min || n > max)
    throw coded("INVALID_INPUT", `${name} must be an integer from ${min} to ${max}`);
  return n;
}

// Returns { claims, times } where claims is a shallow copy with omitted registered claims removed and
// times lists the setters to call: { exp?, nbf?, iat? } as absolute seconds.
function applyTimeModes(config, input, now) {
  if (!isPlainObject(input)) throw coded("INVALID_CLAIMS");
  const claims = { ...input };
  const times = {};
  switch (config.expiryMode === undefined ? "ttl" : config.expiryMode) {
    case "ttl":
      times.exp = now + intOption(config.ttlSeconds, { name: "ttlSeconds", min: 1, max: YEAR, fallback: 3600 });
      break;
    case "absolute":
      times.exp = intOption(config.expiresAt, { name: "expiresAt", min: 0, max: Number.MAX_SAFE_INTEGER });
      break;
    case "preserve":
      break;
    case "omit":
      delete claims.exp;
      break;
    default:
      throw coded("INVALID_INPUT", "unknown expiry mode");
  }
  switch (config.notBeforeMode === undefined ? "preserve" : config.notBeforeMode) {
    case "offset":
      times.nbf =
        now + intOption(config.notBeforeSeconds, { name: "notBeforeSeconds", min: -YEAR, max: YEAR, fallback: 0 });
      break;
    case "absolute":
      times.nbf = intOption(config.notBeforeAt, { name: "notBeforeAt", min: 0, max: Number.MAX_SAFE_INTEGER });
      break;
    case "preserve":
      break;
    case "omit":
      delete claims.nbf;
      break;
    default:
      throw coded("INVALID_INPUT", "unknown not-before mode");
  }
  if (config.issuedAt === undefined || config.issuedAt === true) times.iat = now;
  else if (config.issuedAt !== false) throw coded("INVALID_INPUT", "issuedAt must be true or false");
  return { claims, times };
}

// Protected header for producers: typ defaults to JWT, blank omits it; alg comes from the key state.
function protectedHeader(config, alg, extra = {}) {
  const header = { alg, ...extra };
  const typ = config.typ === undefined ? "JWT" : config.typ;
  if (typeof typ !== "string") throw coded("INVALID_INPUT", "typ must be a string");
  if (typ !== "") header.typ = typ;
  return header;
}

// Used only after a failed signing TypeError to distinguish jose's native serialization failure
// from a key/crypto error. Successful signing keeps jose's single clone/serialization path.
function assertSerializableClaims(claims) {
  const snapshot = structuredClone(claims);
  for (const name of ["iat", "nbf", "exp"]) {
    if (typeof snapshot[name] === "number" && !Number.isFinite(snapshot[name])) throw coded("INVALID_CLAIMS");
  }
  JSON.stringify(snapshot);
}

// The token string from the selected input: bounded, optionally Bearer-stripped, compact-serialization shaped.
function extractToken(value, stripBearer) {
  if (typeof value !== "string" || value === "") throw coded("NO_TOKEN");
  if (Buffer.byteLength(value) > MAX_TOKEN_BYTES) throw coded("INPUT_TOO_LARGE");
  let token = value;
  if (stripBearer) {
    const m = /^Bearer +(.*)$/i.exec(value);
    if (m) token = m[1];
  }
  if (!COMPACT_RE.test(token)) throw coded("NO_TOKEN", "value is not a compact JWS or JWE");
  return token;
}

// Consumer claim policy shared by verify and decrypt (M1 subset: typ and requiredClaims).
function consumeOptions(config) {
  const options = {};
  const typ = config.typ === undefined ? "JWT" : config.typ;
  if (typeof typ !== "string") throw coded("INVALID_INPUT", "typ must be a string");
  if (typ !== "") options.typ = typ;
  const required = config.requiredClaims === undefined ? "exp" : config.requiredClaims;
  if (typeof required !== "string") throw coded("INVALID_INPUT", "requiredClaims must be a comma-separated string");
  const list = required
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (list.length) options.requiredClaims = list;
  return options;
}

// Static destination paths: identifier segments, no __proto__, disjoint from each other.
function parsePath(path, label) {
  if (typeof path !== "string" || !PATH_RE.test(path))
    throw coded("INVALID_INPUT", `${label} is not a valid message property path`);
  const segments = path.split(".");
  if (segments.includes("__proto__")) throw coded("INVALID_INPUT", `${label} must not contain __proto__`);
  return segments;
}
function assertDisjoint(a, b, labels) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return;
  throw coded("INVALID_INPUT", `${labels[0]} and ${labels[1]} must not be the same or nested`);
}

// Every existing intermediate must be a plain object holding own data properties; a missing branch needs an
// extensible parent; an existing target must be a writable data property. Nothing is mutated here.
function preflight(msg, segments) {
  let obj = msg;
  for (let i = 0; i < segments.length; i++) {
    const key = segments[i];
    const where = segments.slice(0, i + 1).join(".");
    const desc = Object.getOwnPropertyDescriptor(obj, key);
    if (desc === undefined) {
      if (!Object.isExtensible(obj)) throw coded("OUTPUT_INVALID", `cannot create msg.${where}`);
      return;
    }
    if (!("value" in desc)) throw coded("OUTPUT_INVALID", `msg.${where} is an accessor`);
    if (i === segments.length - 1) {
      if (!desc.writable) throw coded("OUTPUT_INVALID", `msg.${where} is read-only`);
      return;
    }
    if (!isPlainObject(desc.value)) throw coded("OUTPUT_INVALID", `msg.${where} is not a plain object`);
    obj = desc.value;
  }
}

// Preflight all writes, then commit them with RED.util.setMessageProperty and check every return value.
function writeOutputs(RED, msg, writes) {
  for (const [segments] of writes) preflight(msg, segments);
  for (const [segments, value] of writes) {
    if (RED.util.setMessageProperty(msg, segments.join("."), value, true) === false)
      throw coded("OUTPUT_INVALID", `msg.${segments.join(".")} could not be written`);
  }
}

// Second-output shape: { code, message, claim?, reason? }; a previous msg.error moves to msg._error like Catch does.
function rejectMsg(msg, err) {
  preflight(msg, ["error"]);
  if (msg.error !== undefined) preflight(msg, ["_error"]);
  if (msg.error !== undefined) msg._error = msg.error;
  const error = { code: err.code, message: err.message };
  if (err.claim) error.claim = err.claim;
  if (err.reason) error.reason = err.reason;
  msg.error = error;
  return msg;
}

module.exports = {
  MAX_TOKEN_BYTES,
  isPlainObject,
  intOption,
  applyTimeModes,
  protectedHeader,
  assertSerializableClaims,
  extractToken,
  consumeOptions,
  parsePath,
  assertDisjoint,
  preflight,
  writeOutputs,
  rejectMsg,
};
