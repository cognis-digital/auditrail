#!/usr/bin/env node
// JavaScript port of the AUDITRAIL core — mirrors the Python `chain`/`verify`/`attest`
// command surface and produces byte-identical hash-chain digests (sha256 over
// prev || 0x1f || canonical-json(event)). Zero dependencies, stdlib `crypto` only.
import { createHash } from "crypto";
import { readFileSync } from "fs";
import { pathToFileURL } from "url";

export const GENESIS = "0".repeat(64);
export const REQUIRED_FIELDS = ["ts", "actor", "action"];

// Canonical JSON: sorted keys, no whitespace — matches Python json.dumps(sort_keys, separators).
function canonicalJson(obj) {
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    return JSON.stringify(obj);
  }
  const keys = Object.keys(obj).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k]));
  return "{" + parts.join(",") + "}";
}

// Build the canonical payload for an event: core triple first, extras never shadow it.
export function canonicalEvent(ev) {
  const payload = { ts: ev.ts, actor: ev.actor, action: ev.action };
  for (const [k, v] of Object.entries(ev.extra || {})) {
    if (!(k in payload)) payload[k] = v;
  }
  return payload;
}

function linkDigest(prev, ev) {
  const material = prev + "\x1f" + canonicalJson(canonicalEvent(ev));
  return createHash("sha256").update(Buffer.from(material, "utf-8")).digest("hex");
}

export function fromRaw(raw, i) {
  const missing = REQUIRED_FIELDS.filter(
    (f) => !(f in raw) || raw[f] === null || raw[f] === ""
  );
  if (missing.length) {
    throw new Error(`event ${i}: missing required field(s): ${missing.join(", ")}`);
  }
  const extra = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!REQUIRED_FIELDS.includes(k)) extra[k] = v;
  }
  return { ts: String(raw.ts), actor: String(raw.actor), action: String(raw.action), extra };
}

export function loadEvents(text) {
  text = text.trim();
  if (!text) return [];
  let records;
  if (text[0] === "[") {
    records = JSON.parse(text);
    if (!Array.isArray(records)) throw new Error("top-level JSON must be an array of events");
  } else {
    records = [];
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      try {
        records.push(JSON.parse(line));
      } catch (e) {
        throw new Error(`line ${i + 1}: invalid JSON: ${e.message}`);
      }
    }
  }
  return records.map((r, i) => {
    if (typeof r !== "object" || r === null || Array.isArray(r)) {
      throw new Error(`event ${i} is not an object`);
    }
    return fromRaw(r, i);
  });
}

export function buildChain(events) {
  const links = [];
  let prev = GENESIS;
  events.forEach((ev, i) => {
    const digest = linkDigest(prev, ev);
    links.push({ index: i, prev, digest, event: ev });
    prev = digest;
  });
  return links;
}

export function head(links) {
  return links.length ? links[links.length - 1].digest : GENESIS;
}

export function verifyChain(links) {
  const breaks = [];
  let prev = GENESIS;
  for (const link of links) {
    if (link.prev !== prev) {
      breaks.push({
        index: link.index,
        reason: "prev-pointer mismatch",
        expected_prev: prev,
        stored_prev: link.prev,
        action: link.event.action,
      });
    }
    const recomputed = linkDigest(link.prev, link.event);
    if (recomputed !== link.digest) {
      breaks.push({
        index: link.index,
        reason: "digest mismatch (content altered)",
        expected_digest: recomputed,
        stored_digest: link.digest,
        action: link.event.action,
      });
      prev = link.digest;
    } else {
      prev = recomputed;
    }
  }
  return breaks;
}

export function attest(links, source = "<stdin>") {
  const breaks = verifyChain(links);
  const actors = [...new Set(links.map((l) => l.event.actor))].sort();
  const manifest = {
    tool: "auditrail",
    version: "1.0.0",
    source,
    attested_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    event_count: links.length,
    genesis: GENESIS,
    head: head(links),
    first_ts: links.length ? links[0].event.ts : null,
    last_ts: links.length ? links[links.length - 1].event.ts : null,
    distinct_actors: actors,
    intact: breaks.length === 0,
    break_count: breaks.length,
  };
  manifest.manifest_digest = createHash("sha256")
    .update(Buffer.from(canonicalJson(manifest), "utf-8"))
    .digest("hex");
  return manifest;
}

function readInput(path) {
  if (!path || path === "-") return readFileSync(0, "utf-8");
  return readFileSync(path, "utf-8");
}

function main(argv) {
  const cmd = argv[0];
  const input = argv[1] || "-";
  if (!["chain", "verify", "attest"].includes(cmd)) {
    process.stderr.write("usage: auditrail.js <chain|verify|attest> [file]\n");
    return 1;
  }
  let links;
  try {
    links = buildChain(loadEvents(readInput(input)));
  } catch (e) {
    process.stderr.write(`error: ${e.message}\n`);
    return 1;
  }
  if (cmd === "chain") {
    console.log(JSON.stringify({ head: head(links), event_count: links.length, links }, null, 2));
    return 0;
  }
  if (cmd === "verify") {
    const breaks = verifyChain(links);
    console.log(
      JSON.stringify(
        { intact: breaks.length === 0, event_count: links.length, break_count: breaks.length, breaks },
        null,
        2
      )
    );
    return breaks.length ? 2 : 0;
  }
  const manifest = attest(links, input === "-" ? "<stdin>" : input);
  console.log(JSON.stringify(manifest, null, 2));
  return manifest.intact ? 0 : 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
