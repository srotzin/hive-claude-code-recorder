#!/usr/bin/env node
// recorderd: the Hive recorder as a small service, for running the signing keys and the record
// outside the agent's reach. Run it as a different user, in a sidecar container, or on the host
// that starts the agent's sandbox. Point the hook at it with HIVE_RECORDER_URL.
//
//   HIVE_RECORDER_DIR=/var/lib/hive-recorder HIVE_ADMISSION=/etc/hive/admission.json \
//   HIVE_RECORDERD_PORT=18890 node recorderd.mjs
//
// It accepts one thing: a described event (fingerprints, sizes, tool names, touched paths and hosts).
// It never accepts or stores prompts, tool input, tool output or file content. The admission is
// read from HIVE_ADMISSION, which the agent can't edit, and signed as line 1 of every new session.
// Witnesses and timestamp authorities are called from here, so their statements land outside the
// agent's reach too.
import http from "node:http";
import fs from "node:fs";
import { appendDesc, outsideJob, sendOutside } from "./record.mjs";
import { scopeOf } from "./core.mjs";

const dir = process.env.HIVE_RECORDER_DIR;
if (!dir) { console.error("HIVE_RECORDER_DIR is required, and should be a directory the agent can't read"); process.exit(1); }
const admFile = process.env.HIVE_ADMISSION;
const admission = admFile ? (() => { const p = JSON.parse(fs.readFileSync(admFile, "utf8")); return { policy: p, scope: scopeOf(p) }; })() : null;
const ID = /^[A-Za-z0-9_-]{1,120}$/;
const EVENT = /^[A-Za-z]{1,40}$/;
// Fields a description may carry. Anything else is refused, so content can't be smuggled in.
const ALLOWED = new Set(["event", "session", "prompt_id", "agent", "permission_mode", "fp_cwd", "tool", "fp", "bytes", "duration_ms", "interrupted", "source", "model", "reason"]);
const HEX = /^[0-9a-f]{64}$/;

function check(b) {
  if (!b || typeof b !== "object" || !ID.test(String(b.session_id || ""))) return "session_id must be 1 to 120 letters, digits, - or _";
  const d = b.desc;
  if (!d || typeof d !== "object" || !EVENT.test(String(d.event || ""))) return "desc.event is not a known hook event";
  for (const k of Object.keys(d)) if (!ALLOWED.has(k)) return "desc has a field recorderd does not accept: " + k;
  if (d.fp) for (const v of Object.values(d.fp)) if (!HEX.test(v)) return "fingerprints must be 64 hex characters";
  if (d.bytes) for (const v of Object.values(d.bytes)) if (!Number.isInteger(v)) return "byte sizes must be integers";
  if (d.tool && (typeof d.tool.name !== "string" || d.tool.name.length > 200)) return "bad tool name";
  if (b.touched != null) {
    const t = b.touched;
    if (!Array.isArray(t.paths) || !Array.isArray(t.hosts) || t.paths.length > 200 || t.hosts.length > 200) return "touched must be { paths: [], hosts: [], datasets?: [] }";
    if (t.datasets !== undefined && (!Array.isArray(t.datasets) || t.datasets.length > 200)) return "touched.datasets must be a list";
    if (Object.keys(t).some(k => !["paths", "hosts", "datasets"].includes(k))) return "touched may only hold paths, hosts and datasets";
    if ([...t.paths, ...t.hosts, ...(t.datasets || [])].some(x => typeof x !== "string" || x.length > 1024)) return "touched entries must be short strings";
  }
  return null;
}

const send = (res, code, obj) => { res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" }); res.end(JSON.stringify(obj)); };
http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true, service: "hive-recorderd", admission: admission ? admission.scope : null });
  if (req.method !== "POST" || req.url !== "/v1/event") return send(res, 404, { error: "POST /v1/event" });
  let raw = "";
  req.on("data", c => { raw += c; if (raw.length > 65536) req.destroy(); });
  req.on("end", async () => {
    let b; try { b = JSON.parse(raw); } catch { return send(res, 400, { error: "body must be JSON" }); }
    const bad = check(b); if (bad) return send(res, 400, { error: bad });
    try {
      const r = appendDesc(b.session_id, b.desc, b.touched, { dir, admission });
      // With HIVE_WITNESS_WAIT_MS set, answer the hook only after the witnesses have signed (or the wait
      // runs out), so a statement exists before the tool call runs. Without it, witness in the background.
      if (Number(process.env.HIVE_WITNESS_WAIT_MS || 0) > 0) await sendOutside(outsideJob(r)).catch(() => {});
      send(res, 200, { ok: true, seq: r.last.seq });
      if (!(Number(process.env.HIVE_WITNESS_WAIT_MS || 0) > 0)) sendOutside(outsideJob(r)).catch(() => {});
    } catch (e) { send(res, 500, { error: "could not append" }); }
  });
}).listen(Number(process.env.HIVE_RECORDERD_PORT || 18890), process.env.HIVE_RECORDERD_HOST || "127.0.0.1", () => console.log("hive-recorderd on", process.env.HIVE_RECORDERD_PORT || 18890, admission ? "with admission" : "without admission"));
