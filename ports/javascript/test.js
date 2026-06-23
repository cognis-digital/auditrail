#!/usr/bin/env node
// Smoke test for the JS port. Asserts parity with the Python reference head and
// core invariants. Run: `node test.js` (exit 0 = pass).
import assert from "assert";
import {
  GENESIS,
  loadEvents,
  buildChain,
  head,
  verifyChain,
  attest,
} from "./index.js";

const SAMPLE = JSON.stringify([
  { ts: "2026-06-08T09:00:00Z", actor: "alice", action: "login" },
  { ts: "2026-06-08T09:01:00Z", actor: "alice", action: "read", resource: "r1" },
  { ts: "2026-06-08T09:02:00Z", actor: "bob", action: "delete", resource: "r1" },
]);

// Reference head computed by the Python implementation over the same sample.
const REFERENCE_HEAD =
  "8ae3d48a5736f485bd64d7d812d5255a5548962684e79a85d05bbbfac1ea94d3";

let n = 0;
function ok(name, fn) {
  fn();
  n++;
  console.log("ok -", name);
}

ok("builds three links", () => {
  const links = buildChain(loadEvents(SAMPLE));
  assert.strictEqual(links.length, 3);
  assert.strictEqual(links[0].prev, GENESIS);
});

ok("byte-identical head vs python reference", () => {
  const links = buildChain(loadEvents(SAMPLE));
  assert.strictEqual(head(links), REFERENCE_HEAD);
});

ok("intact chain verifies clean", () => {
  const links = buildChain(loadEvents(SAMPLE));
  assert.deepStrictEqual(verifyChain(links), []);
});

ok("deterministic head", () => {
  assert.strictEqual(head(buildChain(loadEvents(SAMPLE))), head(buildChain(loadEvents(SAMPLE))));
});

ok("tamper is detected", () => {
  const links = buildChain(loadEvents(SAMPLE));
  links[1].event.actor = "mallory"; // mutate content, keep stored digest
  const breaks = verifyChain(links);
  assert.ok(breaks.length > 0);
  assert.strictEqual(breaks[0].index, 1);
});

ok("missing required field rejected", () => {
  assert.throws(() => loadEvents('[{"actor":"a","action":"x"}]'));
});

ok("jsonl parses", () => {
  const jsonl = '{"ts":"t1","actor":"a","action":"x"}\n{"ts":"t2","actor":"b","action":"y"}';
  assert.strictEqual(loadEvents(jsonl).length, 2);
});

ok("attest manifest is well-formed", () => {
  const links = buildChain(loadEvents(SAMPLE));
  const m = attest(links, "sample");
  assert.strictEqual(m.intact, true);
  assert.strictEqual(m.event_count, 3);
  assert.strictEqual(m.head, REFERENCE_HEAD);
  assert.deepStrictEqual(m.distinct_actors, ["alice", "bob"]);
  assert.ok(m.manifest_digest);
});

ok("empty input yields genesis head", () => {
  assert.strictEqual(head(buildChain(loadEvents(""))), GENESIS);
});

console.log(`\n${n} assertions passed`);
