"use strict";
// Measurement, not a gate: raw jose versus deployed flows, and a burst against a stalled JWKS endpoint.
// Run with `npm run bench`; paste the printed table into README.md. Numbers depend on the machine.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const http = require("node:http");
const crypto = require("node:crypto");
const { once } = require("node:events");
const jose = require("jose");
const { startNodeRed } = require("../test/helpers/node-red");
const { pairs, jwk } = require("../test/helpers/keys");

const PKG = path.resolve(__dirname, "..");
const N = Number(process.env.BENCH_N ?? 1000);
const SECRET = crypto.randomBytes(32);
assert.ok(Number.isSafeInteger(N) && N > 0, "BENCH_N must be a positive safe integer");
const rows = [];
let nr;

test.before(async () => {
  nr = await startNodeRed({ packageDir: PKG, timeoutMs: 120_000 });
});
test.after(async () => {
  await nr?.stop();
  const width = rows.reduce((w, r) => Math.max(w, r[0].length), 0);
  console.log(
    `\nMachine: ${os.cpus()[0]?.model ?? "unknown"} available CPUs=${os.availableParallelism()}, Node ${process.version}, jose ${require("jose/package.json").version}, Node-RED ${require("node-red/package.json").version}, N=${N}, claims UTF-8 bytes=${Buffer.byteLength(JSON.stringify({ sub: "bench", i: N - 1 }))}\n`,
  );
  console.log(
    `| ${"Scenario".padEnd(width)} | messages/s | p50 ms | p95 ms | peak RSS MB |\n| ${"-".repeat(width)} | ---: | ---: | ---: | ---: |`,
  );
  for (const [name, rate, p50, p95, rss] of rows)
    console.log(`| ${name.padEnd(width)} | ${rate} | ${p50} | ${p95} | ${rss} |`);
});

// Peak resident set of the Node-RED child, from /proc on Linux; blank elsewhere.
const rssMb = (field = "VmHWM") => {
  try {
    const m = new RegExp(`${field}:\\s+(\\d+) kB`).exec(fs.readFileSync(`/proc/${nr.child.pid}/status`, "utf8"));
    return m ? (Number(m[1]) / 1024).toFixed(0) : "";
  } catch {
    return "";
  }
};
const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];

test("raw jose baselines with sequential and burst scheduling", async () => {
  for (const [name, alg, key, pub] of [
    ["raw jose HS256 sign+verify", "HS256", SECRET, SECRET],
    ["raw jose RS256 sign+verify", "RS256", pairs.rsa.privateKey, pairs.rsa.publicKey],
  ]) {
    const runOne = async (i, lat) => {
      const t0 = process.hrtime.bigint();
      const token = await new jose.SignJWT({ sub: "bench", i })
        .setProtectedHeader({ alg, typ: "JWT" })
        .setIssuedAt()
        .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
        .sign(key);
      const { payload } = await jose.jwtVerify(token, pub, { algorithms: [alg], typ: "JWT", requiredClaims: ["exp"] });
      assert.equal(payload.i, i);
      lat.push(Number(process.hrtime.bigint() - t0) / 1e6);
    };
    for (const concurrent of [false, true]) {
      for (let pass = 0; pass < 2; pass++) {
        const lat = [];
        const start = process.hrtime.bigint();
        if (concurrent) await Promise.all(Array.from({ length: N }, (_, i) => runOne(i, lat)));
        else for (let i = 0; i < N; i++) await runOne(i, lat);
        const seconds = Number(process.hrtime.bigint() - start) / 1e9;
        lat.sort((a, b) => a - b);
        if (pass === 1)
          rows.push([
            `${name} ${concurrent ? "burst" : "sequential"}`,
            Math.round(N / seconds),
            pct(lat, 50).toFixed(2),
            pct(lat, 95).toFixed(2),
            "",
          ]);
      }
    }
  }
});

// Function node generator -> sign -> verify -> Function node sink that reports totals once N messages arrived.
const generator = `for (let i = 0; i < ${N}; i++) node.send({ payload: { sub: "bench", i }, seq: i, t0: Date.now() }); return null;`;
// Elapsed runs from the earliest generated t0 to the last arrival, so it covers queueing, not just the arrival wave.
const sink = `const c = context.get("c") || { n: 0, t0: Infinity, lat: [], success: 0, errors: {}, seen: {}, duplicates: 0, invalid: 0 };
c.n++; c.t0 = Math.min(c.t0, msg.t0); c.lat.push(Date.now() - msg.t0);
if (c.seen[msg.seq]) c.duplicates++;
c.seen[msg.seq] = true;
if (msg.error) c.errors[msg.error.code] = (c.errors[msg.error.code] || 0) + 1;
else if (msg.payload?.sub === "bench" && msg.payload.i === msg.seq) c.success++;
else c.invalid++;
if (c.n < ${N}) { context.set("c", c); return null; }
context.set("c", undefined);
c.lat.sort((a, b) => a - b);
const p = (q) => c.lat[Math.min(c.lat.length - 1, Math.floor((q / 100) * c.lat.length))];
return { payload: { n: c.n, ms: Date.now() - c.t0, p50: p(50), p95: p(95), success: c.success, errors: c.errors, duplicates: c.duplicates, invalid: c.invalid } };`;

function assertOutcomes(result, errorCode) {
  assert.equal(result.n, N, "all inputs reached a terminal route");
  assert.equal(result.duplicates, 0, "no duplicate terminal outcomes");
  assert.equal(result.invalid, 0, "verified claims match the generated input");
  assert.equal(result.success, errorCode ? 0 : N, "expected successful verifications");
  assert.deepEqual(result.errors, errorCode ? { [errorCode]: N } : {}, "expected error counts and codes");
}

async function deployedFlow(name, keyNode) {
  const id = name.replace(/\W+/g, "_");
  const flow = [
    { id: `t_${id}`, type: "tab", label: name },
    keyNode(`k_${id}`),
    {
      id: `i_${id}`,
      type: "inject",
      z: `t_${id}`,
      props: [{ p: "payload" }],
      payload: "",
      payloadType: "date",
      wires: [[`g_${id}`]],
    },
    { id: `g_${id}`, type: "function", z: `t_${id}`, func: generator, outputs: 1, wires: [[`s_${id}`]] },
    {
      id: `s_${id}`,
      type: "jose-sign",
      z: `t_${id}`,
      key: `k_${id}`,
      claims: "payload",
      claimsType: "msg",
      tokenTo: "payload",
      tokenToType: "msg",
      wires: [[`v_${id}`]],
    },
    {
      id: `v_${id}`,
      type: "jose-verify",
      z: `t_${id}`,
      key: `k_${id}`,
      tokenFrom: "payload",
      tokenFromType: "msg",
      claimsTo: "payload",
      claimsToType: "msg",
      failureMode: "catch",
      wires: [[`z_${id}`], [`z_${id}`]],
    },
    { id: `z_${id}`, type: "function", z: `t_${id}`, func: sink, outputs: 1, wires: [[`d_${id}`]] },
    {
      id: `d_${id}`,
      type: "debug",
      z: `t_${id}`,
      active: true,
      tosidebar: true,
      complete: "payload",
      targetType: "msg",
      wires: [],
    },
    { id: `c_${id}`, type: "catch", z: `t_${id}`, scope: null, uncaught: false, wires: [[`z_${id}`]] },
  ];
  await nr.deploy(flow);
  // First pass warms JIT and WebCrypto; the second pass is the measurement.
  let r;
  for (let pass = 0; pass < 2; pass++) {
    const [d] = await Promise.all([nr.waitForDebug((m) => m.id === `d_${id}`, 120_000), nr.inject(`i_${id}`)]);
    r = d.msg;
    assertOutcomes(r);
  }
  rows.push([name, Math.round((N / r.ms) * 1000), r.p50, r.p95, rssMb()]);
  return r;
}

test("deployed sign -> verify flows", async () => {
  await deployedFlow("flow HS256 sign -> verify", (id) => ({
    id,
    type: "jose-key",
    name: "hs",
    family: "signing",
    source: "secret",
    alg: "auto",
    secretEncoding: "base64",
    credentials: { secret: SECRET.toString("base64") },
  }));
  await deployedFlow("flow RS256 sign -> verify", (id) => ({
    id,
    type: "jose-key",
    name: "rs",
    family: "signing",
    source: "pem",
    alg: "auto",
    credentials: { pem: pairs.rsa.privateKey.export({ type: "pkcs8", format: "pem" }) },
  }));
});

test("burst against a stalled JWKS endpoint, then recovery", async () => {
  let healthy = false,
    requests = 0;
  const pub = await jwk.public("p256", { kid: "e1", alg: "ES256" });
  const stall = http.createServer((req, res) => {
    requests++;
    if (healthy) {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ keys: [pub] }));
    }
  });
  stall.listen(0, "127.0.0.1");
  await once(stall, "listening");
  try {
    const token = await new jose.SignJWT({ sub: "burst" })
      .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "e1" })
      .setExpirationTime("1h")
      .sign(pairs.p256.privateKey);
    const key = (url) => (id) => ({
      id,
      type: "jose-key",
      name: "remote",
      family: "signing",
      source: "remote-jwks",
      algorithms: "ES256",
      url,
      allowInsecureLoopback: true,
      cacheSeconds: 60,
      timeoutSeconds: 1,
    });
    const id = "burst";
    const gen = `for (let i = 0; i < ${N}; i++) node.send({ payload: ${JSON.stringify(token)}, seq: i, t0: Date.now() }); return null;`;
    const flow = (url) => [
      { id: `t_${id}`, type: "tab", label: id },
      key(url)(`k_${id}`),
      {
        id: `i_${id}`,
        type: "inject",
        z: `t_${id}`,
        props: [{ p: "payload" }],
        payload: "",
        payloadType: "date",
        wires: [[`g_${id}`]],
      },
      { id: `g_${id}`, type: "function", z: `t_${id}`, func: gen, outputs: 1, wires: [[`v_${id}`]] },
      {
        id: `v_${id}`,
        type: "jose-verify",
        z: `t_${id}`,
        key: `k_${id}`,
        tokenFrom: "payload",
        tokenFromType: "msg",
        claimsTo: "payload",
        claimsToType: "msg",
        failureMode: "catch",
        wires: [[`z_${id}`], []],
      },
      {
        id: `z_${id}`,
        type: "function",
        z: `t_${id}`,
        func: sink.replace('msg.payload?.sub === "bench" && msg.payload.i === msg.seq', 'msg.payload?.sub === "burst"'),
        outputs: 1,
        wires: [[`d_${id}`]],
      },
      {
        id: `d_${id}`,
        type: "debug",
        z: `t_${id}`,
        active: true,
        tosidebar: true,
        complete: "payload",
        targetType: "msg",
        wires: [],
      },
      { id: `c_${id}`, type: "catch", z: `t_${id}`, scope: null, uncaught: false, wires: [[`z_${id}`]] },
    ];
    await nr.deploy(flow(`http://127.0.0.1:${stall.address().port}/jwks`));
    const before = rssMb("VmRSS");
    const requested = once(stall, "request", { signal: AbortSignal.timeout(10_000) });
    const finished = nr.waitForDebug((m) => m.id === `d_${id}`, 30_000);
    const pending = Promise.all([finished, nr.inject(`i_${id}`), requested]);
    await requested;
    const during = rssMb("VmRSS");
    const [d] = await pending;
    assertOutcomes(d.msg, "ERR_JWKS_TIMEOUT");
    assert.equal(requests, 1, "the burst shares one remote fetch");
    const after = rssMb("VmRSS");
    rows.push([
      `burst ${N} x verify, JWKS stalled (1 s timeout)`,
      `all settled in ${d.msg.ms} ms`,
      d.msg.p50,
      d.msg.p95,
      rssMb(),
    ]);
    // Retry without redeploy: the same resolver must recover after its failed fetch.
    healthy = true;
    const [retry] = await Promise.all([nr.waitForDebug((m) => m.id === `d_${id}`, 30_000), nr.inject(`i_${id}`)]);
    assertOutcomes(retry.msg);
    assert.equal(requests, 2, "same-config recovery shares one new fetch");
    console.log(
      `Burst outcomes: ${N} ERR_JWKS_TIMEOUT, 0 successes, 0 duplicates; same-config recovery: ${N} successes. Current RSS MB before/at first request/after timeout/after recovery: ${before}/${during}/${after}/${rssMb("VmRSS")}. Cumulative peak: ${rssMb()} MB. No forced GC; snapshots do not measure retained bytes per message.`,
    );
    // Recovery: a fresh key configuration (full deploy) fetches from the healthy endpoint; one message must verify.
    await nr.deploy([
      { id: "t_rec", type: "tab", label: "recovery" },
      key(`http://127.0.0.1:${stall.address().port}/jwks`)("k_rec"),
      {
        id: "i_rec",
        type: "inject",
        z: "t_rec",
        props: [{ p: "payload" }],
        payload: token,
        payloadType: "str",
        wires: [["v_rec"]],
      },
      {
        id: "v_rec",
        type: "jose-verify",
        z: "t_rec",
        key: "k_rec",
        tokenFrom: "payload",
        tokenFromType: "msg",
        claimsTo: "payload",
        claimsToType: "msg",
        failureMode: "catch",
        wires: [["d_rec"], []],
      },
      {
        id: "d_rec",
        type: "debug",
        z: "t_rec",
        active: true,
        tosidebar: true,
        complete: "payload",
        targetType: "msg",
        wires: [],
      },
    ]);
    const [r] = await Promise.all([nr.waitForDebug((m) => m.id === "d_rec", 30_000), nr.inject("i_rec")]);
    assert.equal(r.msg.sub, "burst", "a message verifies against the healthy endpoint after redeploy");
  } finally {
    stall.closeAllConnections();
    stall.close();
  }
});
