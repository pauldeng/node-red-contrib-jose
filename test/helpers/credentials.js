"use strict";
// Deliberately invalid, non-secret fixtures. Equal-size replacements expose tests that only count bytes/lines.
const values = {
  pem: ["", "TEST PEM\nAAAA\nBBBB", "TEST PEM\nCCCC\nDDDD"],
  jwk: ["", '{\n  "test": "AAAA"\n}', '{\n  "test": "BBBB"\n}'],
};
const path = require("node:path");

const settings = {
  nodesDir: [path.resolve(__dirname, "../.."), path.resolve(__dirname, "../fixtures")],
};
function flow(property = "pem") {
  return [
    { id: "tab1", type: "tab", label: "credential probe" },
    {
      id: "key1",
      type: "jose-key",
      name: "k",
      family: "signing",
      source: property,
      credentials: { [property]: values[property][1] },
    },
    {
      id: "inject1",
      type: "inject",
      z: "tab1",
      props: [{ p: "payload" }],
      payload: "",
      payloadType: "date",
      repeat: "",
      onceDelay: 0.1,
      wires: [["probe1"]],
    },
    { id: "probe1", type: "test-credential-probe", z: "tab1", key: "key1", wires: [["debug1"]] },
    { id: "debug1", type: "debug", z: "tab1", active: true, tosidebar: true, complete: "payload" },
  ];
}
async function observe(nr) {
  const [result] = await Promise.all([nr.waitForDebug((d) => d.id === "debug1"), nr.inject("inject1")]);
  return result.msg;
}
module.exports = { values, settings, flow, observe };
