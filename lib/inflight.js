"use strict";
const { sanitize } = require("./errors");
// One completion per input, even when close() races an awaited stage.
// track(done) returns finish(fn): fn runs at most once and never after the node closed the entry.
function createInflight() {
  const pending = new Set();
  return {
    track(done) {
      let completed = false;
      const complete = (err) => {
        if (completed) return;
        completed = true;
        done(err);
      };
      const entry = { done: complete };
      pending.add(entry);
      return (fn) => {
        if (!pending.delete(entry)) return false;
        try {
          fn(complete);
        } catch (err) {
          complete(sanitize(err, "output"));
        }
        return true;
      };
    },
    // Settle everything still pending with `err` and forget it; later finish() calls become no-ops.
    closeAll(err) {
      const entries = [...pending];
      pending.clear();
      for (const { done } of entries) done(sanitize(err));
      return entries.length;
    },
    get size() {
      return pending.size;
    },
  };
}
module.exports = { createInflight };
