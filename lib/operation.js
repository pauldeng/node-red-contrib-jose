"use strict";
// The one input handler behind the four operation nodes: static setup validated once, one completion per input,
// stage-attributed sanitising, close guards after every await, and Catch-versus-rejection routing.
const { promisify } = require("node:util");
const crypto = require("node:crypto");
const { coded, sanitize, REJECTION_CODES } = require("./errors");
const { createInflight } = require("./inflight");
const {
  applyTimeModes,
  protectedHeader,
  assertSerializableClaims,
  extractToken,
  consumeOptions,
  parsePath,
  assertDisjoint,
  writeOutputs,
  rejectMsg,
} = require("./jwt");

const INPUT_TYPES = {
  produce: ["msg", "flow", "global", "json", "jsonata"],
  consume: ["msg", "flow", "global", "jsonata"],
};
const or = (value, fallback) => (value === undefined ? fallback : value);
// Producer claim/header setters: literal or dynamic; a blank literal leaves the incoming claim alone.
const SETTER_TYPES = ["str", "msg", "flow", "global", "env"];
const SETTERS = {
  issuer: { types: SETTER_TYPES, apply: "setIssuer", claim: "iss" },
  subject: { types: SETTER_TYPES, apply: "setSubject", claim: "sub" },
  audience: { types: [...SETTER_TYPES, "json"], apply: "setAudience", claim: "aud" },
  jti: { types: [...SETTER_TYPES, "uuid"], apply: "setJti", claim: "jti" },
  kid: { types: SETTER_TYPES },
};

function checkSource(value, type, kind) {
  if (typeof value !== "string" || value.trim() === "" || !INPUT_TYPES[kind].includes(type))
    throw coded("INVALID_INPUT", "invalid input source or type");
}

// Producer configuration (sign, encrypt): claims source, time modes, typ, destination. Throws coded errors.
function producerSetup(f) {
  if (or(f.tokenToType, "msg") !== "msg") throw coded("INVALID_INPUT", "tokenTo must be a message property");
  const setup = {
    source: or(f.claims, "payload"),
    sourceType: or(f.claimsType, "msg"),
    time: {
      expiryMode: f.expiryMode,
      ttlSeconds: f.ttlSeconds,
      expiresAt: f.expiresAt,
      notBeforeMode: f.notBeforeMode,
      notBeforeSeconds: f.notBeforeSeconds,
      notBeforeAt: f.notBeforeAt,
      issuedAt: f.issuedAt,
    },
    header: { typ: f.typ },
    tokenTo: parsePath(or(f.tokenTo, "payload"), "tokenTo"),
    setters: {},
  };
  for (const [name, spec] of Object.entries(SETTERS)) {
    const type = or(f[`${name}Type`], "str");
    const value = type === "uuid" ? "" : or(f[name], "");
    if (typeof value !== "string" || !spec.types.includes(type))
      throw coded("INVALID_INPUT", `${name} has an invalid value or type`);
    if (type === "str" && value.trim() === "") continue;
    setup.setters[name] = { value, type };
  }
  checkSource(setup.source, setup.sourceType, "produce");
  applyTimeModes(setup.time, {}, 0); // dry run: an invalid active mode value is a deploy-time error
  protectedHeader(setup.header, "HS256");
  return setup;
}

// Consumer configuration (verify, decrypt): token source, Bearer policy, claim policy, destination, route.
function consumerSetup(f, defaults) {
  const failureMode = or(f.failureMode, "catch");
  if (!["catch", "output"].includes(failureMode)) throw coded("INVALID_INPUT", "failureMode must be catch or output");
  const stripBearer = or(f.stripBearer, defaults.stripBearer);
  if (typeof stripBearer !== "boolean") throw coded("INVALID_INPUT", "stripBearer must be true or false");
  if (or(f.claimsToType, "msg") !== "msg") throw coded("INVALID_INPUT", "claimsTo must be a message property");
  if (or(f.headerToType, "msg") !== "msg") throw coded("INVALID_INPUT", "headerTo must be a message property");
  const headerTo = or(f.headerTo, "");
  if (typeof headerTo !== "string") throw coded("INVALID_INPUT", "headerTo is not a valid message property path");
  const setup = {
    source: or(f.tokenFrom, "payload"),
    sourceType: or(f.tokenFromType, "msg"),
    stripBearer,
    options: consumeOptions({
      typ: f.typ,
      requiredClaims: f.requiredClaims,
      audience: f.audience,
      issuer: f.issuer,
      subject: f.subject,
      clockTolerance: f.clockTolerance,
      maxTokenAge: f.maxTokenAge,
    }),
    claimsTo: parsePath(or(f.claimsTo, "payload"), "claimsTo"),
    headerTo: headerTo.trim() === "" ? undefined : parsePath(headerTo, "headerTo"),
    failureMode,
  };
  if (setup.headerTo) assertDisjoint(setup.claimsTo, setup.headerTo, ["claimsTo", "headerTo"]);
  checkSource(setup.source, setup.sourceType, "consume");
  return setup;
}

function checkSetter(name, value) {
  if (name === "audience" && Array.isArray(value)) {
    if (!value.length || value.some((v) => typeof v !== "string" || v.trim() === ""))
      throw coded("INVALID_INPUT", "audience must be a string or a non-empty array of strings");
    return value;
  }
  if (typeof value !== "string" || value.trim() === "")
    throw coded("INVALID_INPUT", `${name} must be a non-empty string`);
  return value;
}

// Build the token: claims copy with time modes, protected header from the key state, jose builder from `make`.
async function produce({ input, key, state, setup, msg, ctx, isClosing, evaluate, node }, make) {
  const values = {};
  for (const [name, spec] of Object.entries(setup.setters)) {
    ctx.stage = "evaluate";
    let value;
    if (spec.type === "uuid") value = crypto.randomUUID();
    else if (spec.type === "str") value = spec.value;
    else value = await evaluate(spec.value, spec.type, node, msg);
    if (isClosing()) throw coded("NODE_CLOSING");
    values[name] = checkSetter(name, value);
  }
  ctx.stage = "claims";
  const now = Math.floor(Date.now() / 1000);
  const { claims, times } = applyTimeModes(setup.time, input, now);
  const extra = state.enc ? { enc: state.enc } : {};
  const kid = values.kid ?? state.kid;
  if (kid !== undefined) extra.kid = kid;
  const header = protectedHeader(setup.header, state.alg, extra);
  const jwt = make.create(claims).setProtectedHeader(header);
  if (times.iat !== undefined) jwt.setIssuedAt(times.iat);
  if (times.exp !== undefined) jwt.setExpirationTime(times.exp);
  if (times.nbf !== undefined) jwt.setNotBefore(times.nbf);
  for (const [name, spec] of Object.entries(SETTERS))
    if (spec.apply && values[name] !== undefined) jwt[spec.apply](values[name]);
  ctx.stage = "jose";
  try {
    return { writes: [[setup.tokenTo, await make.finalize(jwt, key)]] };
  } catch (err) {
    // jose reports an unserialisable claim as a TypeError; tell it apart from a key/crypto TypeError.
    if (!isClosing() && err instanceof TypeError) {
      try {
        const effective = { ...claims, ...times };
        for (const [name, spec] of Object.entries(SETTERS))
          if (spec.claim && values[name] !== undefined) effective[spec.claim] = values[name];
        assertSerializableClaims(effective);
      } catch {
        throw coded("INVALID_CLAIMS");
      }
    }
    throw err;
  }
}

// Consume the token: shape check, then the jose call supplied by the node with the key state's allowlists.
async function consume({ input, key, state, setup, ctx }, check) {
  ctx.stage = "token";
  const token = extractToken(input, setup.stripBearer);
  ctx.stage = "jose";
  const { payload, protectedHeader: header } = await check(token, key, state, setup.options);
  const writes = [[setup.claimsTo, payload]];
  if (setup.headerTo) writes.push([setup.headerTo, header]);
  return { writes };
}

// Wire a node: `spec.setup()` builds the validated static configuration, `spec.run(ctx)` does the work.
function attach(RED, node, keyNode, spec) {
  const evaluate = promisify(RED.util.evaluateNodeProperty);
  const inflight = createInflight();
  let closing = false;
  let setup;
  try {
    if (keyNode && (keyNode.type !== "jose-key" || typeof keyNode.keyFor !== "function")) throw coded("KEY_UNUSABLE");
    setup = spec.setup();
  } catch (err) {
    setup = { error: sanitize(err, "evaluate") };
  }
  if (!keyNode) node.status({ fill: "red", shape: "ring", text: "no key" });
  else if (!keyNode.state?.ok || keyNode.state.family !== spec.family)
    node.status({ fill: "red", shape: "ring", text: "key error" });
  else if (setup.error) node.status({ fill: "red", shape: "ring", text: "invalid config" });

  node.on("input", async (msg, send, done) => {
    const finish = inflight.track(done);
    const ctx = { stage: "evaluate", isClosing: () => closing };
    try {
      if (closing) throw coded("NODE_CLOSING");
      if (setup.error) throw setup.error;
      if (!keyNode) throw coded("NO_KEY_CONFIG");
      const key = keyNode.keyFor(spec.purpose);
      const input = await evaluate(setup.source, setup.sourceType, node, msg);
      if (closing) throw coded("NODE_CLOSING");
      const result = await spec.run({
        input,
        key,
        state: keyNode.state,
        setup,
        msg,
        ctx,
        isClosing: ctx.isClosing,
        evaluate,
        node,
      });
      if (closing) throw coded("NODE_CLOSING");
      ctx.stage = "output";
      writeOutputs(RED, msg, result.writes);
      finish((complete) => {
        send(spec.kind === "consume" ? [msg, null] : msg);
        complete();
      });
    } catch (err) {
      if (closing) {
        finish((complete) => complete(coded("NODE_CLOSING")));
        return;
      }
      const error = sanitize(err, ctx.stage);
      if (spec.kind === "consume" && setup.failureMode === "output" && REJECTION_CODES.has(error.code)) {
        finish((complete) => {
          send([null, rejectMsg(msg, error)]);
          complete();
        });
        return;
      }
      if (error.code === "INTERNAL_ERROR") node.debug(`${error.code} at stage ${ctx.stage}`);
      finish((complete) => complete(error));
    }
  });

  node.on("close", (removed, done) => {
    closing = true;
    inflight.closeAll(coded("NODE_CLOSING"));
    done();
  });
}

module.exports = { attach, producerSetup, consumerSetup, produce, consume };
