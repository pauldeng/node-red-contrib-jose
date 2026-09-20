"use strict";
// Real Node-RED child with temporary storage and an OS-assigned port (no probe/bind race).
// Register comms waiters BEFORE deploy/inject; they do not replay prior debug messages.
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const { createInterface } = require("node:readline");
const { mkdtemp, rm, writeFile } = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");

async function startNodeRed({ packageDir, settings = {}, timeoutMs = 30_000, log = false } = {}) {
  if (!packageDir) throw new Error("packageDir is required");
  const userDir = await mkdtemp(path.join(os.tmpdir(), "nr-test-"));
  const lines = [];
  const lineWaiters = new Set();
  const commsWaiters = new Set();
  let child, ws, stopping;
  const stop = () =>
    (stopping ??= (async () => {
      ws?.close();
      for (const w of [...lineWaiters, ...commsWaiters]) w.reject(new Error("Node-RED stopped"));
      if (child && child.exitCode === null && child.signalCode === null) {
        const exited = once(child, "exit", { signal: AbortSignal.timeout(10_000) });
        child.kill("SIGTERM");
        try {
          await exited;
        } catch (err) {
          if (err.name !== "AbortError") throw err;
          const killed = once(child, "exit", { signal: AbortSignal.timeout(5_000) });
          child.kill("SIGKILL");
          await killed;
        }
      }
      await rm(userDir, { recursive: true, force: true });
    })());

  const wait = async (set, match, ms, description) => {
    const result = Promise.withResolvers();
    const waiter = { match, resolve: result.resolve, reject: result.reject };
    set.add(waiter);
    const timer = setTimeout(
      () =>
        result.reject(new Error(`timed out waiting for ${description}; last logs:\n${lines.slice(-10).join("\n")}`)),
      ms,
    ); // deadline, cleared on every settle path
    try {
      return await result.promise;
    } finally {
      clearTimeout(timer);
      set.delete(waiter);
    }
  };
  const waitForLog = async (re, { ms = timeoutMs, after = 0 } = {}) => {
    const hit = lines.slice(after).find((l) => re.test(l));
    if (hit) return hit;
    return wait(lineWaiters, (line) => re.test(line), ms, String(re));
  };

  try {
    const settingsFile = path.join(userDir, "settings.js");
    await writeFile(
      settingsFile,
      `module.exports = ${JSON.stringify({
        uiPort: 0,
        uiHost: "127.0.0.1",
        userDir,
        flowFile: "flows.json",
        credentialSecret: "test-secret",
        nodesDir: [packageDir],
        editorTheme: { tours: false, projects: { enabled: false } },
        telemetry: { enabled: false },
        logging: { console: { level: "info", metrics: false, audit: false } },
        ...settings,
      })};\n`,
    );
    child = spawn(process.execPath, [require.resolve("node-red/red.js"), "-u", userDir, "-s", settingsFile], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NODE_ENV: "test" },
    });
    child.on("error", (err) => {
      for (const w of lineWaiters) w.reject(err);
    });
    child.on("exit", () => {
      for (const w of [...lineWaiters, ...commsWaiters])
        w.reject(new Error(`Node-RED exited; ${lines.slice(-10).join("\n")}`));
    });
    for (const stream of [child.stdout, child.stderr]) {
      createInterface({ input: stream }).on("line", (line) => {
        lines.push(line);
        if (log) console.log(`[node-red] ${line}`);
        for (const w of lineWaiters) if (w.match(line)) w.resolve(line);
      });
    }
    const listening = await waitForLog(/Server now running at http/);
    const base = new URL(listening.match(/https?:\/\/\S+/)[0]).origin;
    const port = Number(new URL(base).port);
    await waitForLog(/Started flows/);

    const api = async (method, route, body, headers = {}) => {
      const res = await fetch(base + route, {
        method,
        headers: { "content-type": "application/json", ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`${method} ${route} -> ${res.status} ${await res.text()}`);
      return res.headers.get("content-type")?.includes("json") ? res.json() : res.text();
    };
    const deploy = async (flows, type = "full") => {
      const after = lines.length;
      await api("POST", "/flows", flows, { "Node-RED-Deployment-Type": type });
      // "full" logs "Started flows"; "flows"/"nodes" deploys log "Started modified flows|nodes".
      await waitForLog(/Started (flows|modified flows|modified nodes)/, { after });
    };
    const inject = (id) => api("POST", `/inject/${id}`);
    ws = new WebSocket(`ws://127.0.0.1:${port}/comms`);
    await once(ws, "open", { signal: AbortSignal.timeout(timeoutMs) });
    ws.addEventListener("message", (ev) => {
      for (const { topic, data } of JSON.parse(ev.data)) {
        for (const w of commsWaiters) if (w.match(topic, data)) w.resolve(data);
      }
    });
    const subscribed = new Set();
    const subscribe = (topic) => {
      if (!subscribed.has(topic)) {
        subscribed.add(topic);
        ws.send(JSON.stringify({ subscribe: topic }));
      }
    };
    subscribe("debug");
    const decode = (d) =>
      /^(Object|array|error)/.test(d.format ?? "") && typeof d.msg === "string" ? { ...d, msg: JSON.parse(d.msg) } : d;
    const waitForDebug = async (predicate = () => true, ms = timeoutMs) =>
      decode(
        await wait(commsWaiters, (topic, data) => topic === "debug" && predicate(decode(data)), ms, "debug message"),
      );
    const waitForStatus = (id, predicate = () => true, ms = timeoutMs) => {
      subscribe(`status/${id}`);
      return wait(commsWaiters, (topic, data) => topic === `status/${id}` && predicate(data), ms, `status of ${id}`);
    };
    return {
      port,
      base,
      userDir,
      child,
      lines,
      api,
      deploy,
      inject,
      waitForLog,
      waitForDebug,
      waitForStatus,
      subscribe,
      stop,
    };
  } catch (err) {
    await stop();
    throw err;
  }
}
module.exports = { startNodeRed };
