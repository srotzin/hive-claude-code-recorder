#!/usr/bin/env node
// Hive recorder hook for Claude Code. Reads one hook event on stdin and appends a
// signed, chained line to this session's record.
//
// Rules this file keeps:
//  - It never blocks Claude Code. It always exits 0 and prints nothing to stdout.
//  - It never stores or sends prompt, tool input, tool output or file content.
//    It keeps keyed fingerprints (HMAC-SHA256) and byte sizes only.
//  - The signing key and the fingerprint key are created on this machine and stay here.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { FORMAT, ZERO, canon, checkScope, scopeOf, digestOf, vendorOf, numbersIn } from "./core.mjs";
import { ml_dsa65 } from "./vendor/ml-dsa-65.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DATA = process.env.HIVE_RECORDER_DIR || process.env.CLAUDE_PLUGIN_DATA || path.join(os.homedir(), ".hive-recorder");

function b64u(buf) { return Buffer.from(buf).toString("base64url"); }
function sha256hex(s) { return crypto.createHash("sha256").update(s).digest("hex"); }
function safeId(s) { return String(s || "unknown").replace(/[^A-Za-z0-9_-]/g, "-").slice(0, 120); }

function logError(e) {
  try { fs.mkdirSync(DATA, { recursive: true }); fs.appendFileSync(path.join(DATA, "errors.log"), new Date().toISOString() + " " + (e && e.stack || e) + "\n"); } catch {}
}

// Keys live in DATA/keys. Created once, mode 0600.
export function loadKeys(dir = DATA) {
  const kd = path.join(dir, "keys");
  fs.mkdirSync(kd, { recursive: true, mode: 0o700 });
  const skPath = path.join(kd, "recorder-ed25519.pem"), fkPath = path.join(kd, "fingerprint.key"), pubPath = path.join(kd, "key.json");
  if (!fs.existsSync(skPath)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const tmp = skPath + "." + process.pid;
    fs.writeFileSync(tmp, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    try { fs.linkSync(tmp, skPath); } catch {} // first writer wins if two hooks race
    fs.unlinkSync(tmp);
  }
  if (!fs.existsSync(fkPath)) {
    const tmp = fkPath + "." + process.pid;
    fs.writeFileSync(tmp, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
    try { fs.linkSync(tmp, fkPath); } catch {}
    fs.unlinkSync(tmp);
  }
  const sk = crypto.createPrivateKey(fs.readFileSync(skPath));
  const raw = crypto.createPublicKey(sk).export({ format: "jwk" }).x; // base64url of the 32 byte key
  const keyId = sha256hex(raw).slice(0, 16);
  if (!fs.existsSync(pubPath)) fs.writeFileSync(pubPath, JSON.stringify({ format: FORMAT, alg: "Ed25519", public_key: raw, key_id: keyId, note: "Recorder public key. Give this to whoever will check your records. The private key never leaves this machine." }, null, 2));
  return { sk, pub: raw, keyId, fk: Buffer.from(fs.readFileSync(fkPath, "utf8").trim(), "hex"), kd };
}

// Optional second signature, ML-DSA-65 (FIPS 204). Turned on with HIVE_PQ=1 when a record starts.
function loadPq(kd) {
  const seedPath = path.join(kd, "recorder-ml-dsa-65.seed");
  if (!fs.existsSync(seedPath)) {
    const tmp = seedPath + "." + process.pid;
    fs.writeFileSync(tmp, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
    try { fs.linkSync(tmp, seedPath); } catch {}
    fs.unlinkSync(tmp);
  }
  const k = ml_dsa65.keygen(Uint8Array.from(Buffer.from(fs.readFileSync(seedPath, "utf8").trim(), "hex")));
  return { sk: k.secretKey, pub: b64u(k.publicKey) };
}

// The admission: what this session is allowed to touch, written by whoever starts the agent
// (a sandbox orchestrator, a CI job, a person). Read once, when the record starts.
//   HIVE_ADMISSION=/path/policy.json, or <project>/.claude/hive-admission.json
//   { "purpose": "...", "tools": ["Read","Bash"], "paths": ["**"], "hosts": ["registry.npmjs.org"], "labels": {...} }
export function loadAdmission(cwd) {
  const f = process.env.HIVE_ADMISSION || (cwd ? path.join(cwd, ".claude", "hive-admission.json") : null);
  if (!f || !fs.existsSync(f)) return null;
  const p = JSON.parse(fs.readFileSync(f, "utf8"));
  return { policy: p, scope: scopeOf(p) };
}

// What a tool call touches, as identifiers: file paths and network hosts. Content is never kept.
const HOST_RES = [
  /\b(?:https?|wss?|ftps?|sftp|ssh|git):\/\/(?:[^@\/\s'"]+@)?([A-Za-z0-9.-]+)/g,
  /\bgit@([A-Za-z0-9.-]+):/g,
  /\b(?:scp|rsync)\b[^\n;&|]*?\s(?:[^@\s:]+@)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+):/g,
  /\b(?:ssh|sftp|nc|ncat|telnet)\s+(?:-[A-Za-z]+(?:\s+(?!-)[^\s@]+(?=\s+\S))?\s+)*(?:[^@\s]+@)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g,
];
export function hostsIn(str) {
  const out = new Set();
  for (const re of HOST_RES) for (const m of String(str).matchAll(re)) out.add(m[1].toLowerCase().replace(/\.$/, ""));
  return [...out];
}
export function touchedBy(ev) {
  const i = ev.tool_input && typeof ev.tool_input === "object" ? ev.tool_input : {};
  const cwd = ev.cwd || process.cwd();
  const norm = p => { const abs = path.resolve(cwd, String(p)); const rel = path.relative(cwd, abs); return !rel ? "." : (rel.startsWith("..") || path.isAbsolute(rel)) ? abs : rel; };
  const paths = new Set(), hosts = new Set();
  for (const k of ["file_path", "notebook_path", "path"]) if (typeof i[k] === "string") paths.add(norm(i[k]));
  if ((ev.tool_name === "Glob" || ev.tool_name === "Grep") && typeof i.path !== "string") paths.add(".");
  if (typeof i.command === "string") hostsIn(i.command).forEach(h => hosts.add(h));
  for (const k of ["url", "uri", "endpoint", "base_url"]) if (typeof i[k] === "string") hostsIn(i[k]).forEach(h => hosts.add(h));
  for (const k of ["host", "hostname"]) if (typeof i[k] === "string") hosts.add(i[k].toLowerCase());
  const datasets = new Set();
  for (const k of ["dataset", "dataset_id", "datasets", "feed", "feed_id", "product", "product_id"]) {
    const v = i[k];
    for (const x of Array.isArray(v) ? v : [v]) if (typeof x === "string" && x.length <= 200) datasets.add(x);
  }
  return { paths: [...paths].sort(), hosts: [...hosts].sort(), ...(datasets.size ? { datasets: [...datasets].sort() } : {}) };
}

function fp(fk, v) { return v === undefined ? undefined : crypto.createHmac("sha256", fk).update(canon(v)).digest("hex"); }
function size(v) { return v === undefined ? undefined : Buffer.byteLength(canon(v)); }

// Lock per session so parallel hooks append in a single order.
function withLock(file, fn) {
  const lock = file + ".lock";
  const until = Date.now() + 5000;
  for (;;) {
    try { fs.mkdirSync(lock); break; } catch (e) {
      if (e.code !== "EEXIST") throw e;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > 10000) fs.rmSync(lock, { recursive: true, force: true }); } catch {}
      if (Date.now() > until) throw new Error("lock timeout " + lock);
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5 + Math.floor(Math.random() * 15));
    }
  }
  try { return fn(); } finally { fs.rmSync(lock, { recursive: true, force: true }); }
}

function lastLine(file) {
  if (!fs.existsSync(file)) return null;
  const fd = fs.openSync(file, "r");
  try {
    const st = fs.fstatSync(fd); if (!st.size) return null;
    const n = Math.min(st.size, 65536), buf = Buffer.alloc(n);
    fs.readSync(fd, buf, 0, n, st.size - n);
    const lines = buf.toString("utf8").trimEnd().split("\n");
    return JSON.parse(lines[lines.length - 1]);
  } finally { fs.closeSync(fd); }
}

// Map one Claude Code hook event to the fields we keep. Raw content never enters the line.
export function describe(ev, fk, scope) {
  const e = ev.hook_event_name;
  const d = { event: e, session: ev.session_id };
  if (ev.prompt_id) d.prompt_id = ev.prompt_id;
  if (ev.agent_id) d.agent = { id: ev.agent_id, type: ev.agent_type };
  if (ev.permission_mode) d.permission_mode = ev.permission_mode;
  if (ev.cwd) d.fp_cwd = fp(fk, ev.cwd);
  if (ev.tool_name) {
    d.tool = { name: ev.tool_name, use_id: ev.tool_use_id };
    if (ev.mcp_server && ev.mcp_server.name) d.tool.mcp_server = ev.mcp_server.name;
  }
  const fps = {}, sizes = {};
  const take = (k, v) => { if (v !== undefined) { fps[k] = fp(fk, v); sizes[k] = size(v); } };
  if (e === "PreToolUse") {
    take("input", ev.tool_input);
    if (scope) { const touched = touchedBy(ev); d.scope = { touched, outside: checkScope(scope, ev.tool_name, touched) }; }
  }
  else if (e === "PostToolUse") {
    take("input", ev.tool_input); take("response", ev.tool_response);
    // Answer trail (kept only in split records): the figures in the result, fingerprinted with a
    // per-line nonce for outside checking, and keyed with the fingerprint key for the recorder.
    if (ev.tool_response !== undefined) {
      const nums = numbersIn(typeof ev.tool_response === "string" ? ev.tool_response : canon(ev.tool_response)).slice(0, 500);
      d.nonce = crypto.randomBytes(16).toString("hex");
      d.vals = nums.map(v => sha256hex(d.nonce + "|" + v)).sort();
      d.vals_fk = nums.map(v => fp(fk, "num:" + v)).sort();
    }
  }
  else if (e === "PostToolUseFailure") { take("input", ev.tool_input); take("error", ev.error); if (ev.is_interrupt !== undefined) d.interrupted = !!ev.is_interrupt; }
  else if (e === "UserPromptSubmit") take("prompt", ev.prompt);
  else if (e === "Stop" || e === "SubagentStop") {
    take("last_message", ev.last_assistant_message);
    if (typeof ev.last_assistant_message === "string") {
      d.nonce = crypto.randomBytes(16).toString("hex");
      d.answer_fp = sha256hex(d.nonce + "|" + ev.last_assistant_message);
      d.answer_vals_fk = numbersIn(ev.last_assistant_message).slice(0, 500).map(v => fp(fk, "num:" + v)).sort();
    }
  }
  else if (e === "SessionStart") { d.source = ev.source; if (ev.model) d.model = ev.model; }
  else if (e === "SessionEnd") d.reason = ev.reason;
  else {
    // Any other event: fingerprint the event-specific fields as one value.
    const { session_id, transcript_path, cwd, permission_mode, hook_event_name, prompt_id, ...rest } = ev;
    take("event_fields", rest);
  }
  if (typeof ev.duration_ms === "number") d.duration_ms = ev.duration_ms;
  if (Object.keys(fps).length) { d.fp = fps; d.bytes = sizes; }
  return d;
}

// Append one described event to a session record. Used by the hook (local mode) and by
// recorderd (service mode, where the keys and the record live outside the agent's reach).
//   desc:    output of describe(ev, fk, null)
//   touched: touchedBy(ev) for PreToolUse, else null
//   opts:    { dir, admission: { policy, scope } | null (read once, when the record starts), now }
export function appendDesc(sessionId, desc, touched, { dir = DATA, admission = null, now = () => new Date().toISOString() } = {}) {
  const keys = loadKeys(dir);
  const rd = path.join(dir, "records"); fs.mkdirSync(rd, { recursive: true });
  const file = path.join(rd, safeId(sessionId) + ".jsonl");
  const metaFile = file.replace(/\.jsonl$/, ".meta.json");
  return withLock(file, () => {
    const out = [];
    let last = lastLine(file);
    let meta = null;
    const adm = !last ? admission : null;
    if (!last) {
      const ent = adm && adm.policy.entitlements && typeof adm.policy.entitlements === "object" ? Object.fromEntries(Object.keys(adm.policy.entitlements).sort().map(k => [k, (adm.policy.entitlements[k] || []).map(String).sort()])) : null;
      meta = { pq: process.env.HIVE_PQ === "1", scope: adm ? adm.scope : null, split: process.env.HIVE_SPLIT === "1" || !!ent, entitlements: ent };
      fs.writeFileSync(metaFile, JSON.stringify(meta));
    } else {
      try { meta = JSON.parse(fs.readFileSync(metaFile, "utf8")); } catch { meta = { pq: false, scope: null }; }
    }
    const pq = meta.pq ? loadPq(keys.kd) : null;
    const write = b => {
      const line = { v: FORMAT, seq: last ? last.seq + 1 : 0, prev: last ? last.hash : ZERO, t: now(), key: keys.keyId, ...b };
      if (line.form === "split" && !line.nonce) line.nonce = crypto.randomBytes(16).toString("hex");
      const c = line.form === "split" ? canon(digestOf(line, sha256hex)) : canon(line);
      line.hash = sha256hex(c);
      line.sig = b64u(crypto.sign(null, Buffer.from(c), keys.sk));
      if (pq) line.sig_pq = b64u(ml_dsa65.sign(Buffer.from(c), pq.sk));
      fs.appendFileSync(file, JSON.stringify(line) + "\n");
      out.push(line); last = line;
    };
    if (!last) {
      write({ event: "RecorderKey", session: sessionId, public_key: keys.pub, key_id: keys.keyId, recorder: "hive-recorder/1.3.0", ...(pq ? { pq_alg: "ML-DSA-65", pq_public_key: pq.pub } : {}) });
      if (adm) write({ event: "Admission", session: sessionId, scope: adm.scope, labels: adm.policy.labels || undefined, fp_purpose: fp(keys.fk, adm.policy.purpose), policy_sha256: sha256hex(canon(adm.policy)) });
      // One entitlement line per vendor, so each vendor can be shown its own and nobody else's.
      if (adm && meta.entitlements) for (const [v, ds] of Object.entries(meta.entitlements)) write({ event: "Entitlement", session: sessionId, form: "split", vendor: v, datasets: ds });
    }
    const { vals_fk, answer_fp, answer_vals_fk, ...d0 } = desc;
    const d = { ...d0, session: sessionId };
    if (meta.scope && touched && d.event === "PreToolUse" && d.tool) {
      const sc = meta.entitlements ? { ...meta.scope, datasets: meta.entitlements[vendorOf(d.tool.name)] || [] } : meta.scope;
      d.scope = { touched, outside: checkScope(sc, d.tool.name, touched) };
    }
    const valsFile = file.replace(/\.jsonl$/, ".vals.json");
    if (meta.split) {
      if (d.tool || ["UserPromptSubmit", "Stop", "SubagentStop"].includes(d.event)) { d.form = "split"; const v = d.tool && vendorOf(d.tool.name); if (v) d.vendor = v; }
      if (answer_fp) {
        // Which earlier results this answer repeats figures from. The recorder matches keyed
        // fingerprints, so it never sees the figures themselves.
        let side = {}; try { side = JSON.parse(fs.readFileSync(valsFile, "utf8")); } catch {}
        const mine = new Set(answer_vals_fk || []);
        const drew_on = Object.entries(side).map(([seq, x]) => ({ seq: Number(seq), vendor: x.vendor, matched: x.fk.filter(h => mine.has(h)).length })).filter(x => x.matched > 0).sort((a, b) => a.seq - b.seq);
        d.answer = { fp: answer_fp, drew_on };
      }
    } else { delete d.nonce; delete d.vals; }
    write(d);
    if (meta.split && vals_fk && vals_fk.length) {
      let side = {}; try { side = JSON.parse(fs.readFileSync(valsFile, "utf8")); } catch {}
      side[last.seq] = { vendor: last.vendor, fk: vals_fk };
      fs.writeFileSync(valsFile, JSON.stringify(side), { mode: 0o600 });
    }
    // Seal at the end of each turn and at session end.
    if (d.event === "Stop" || d.event === "SessionEnd") write({ event: "Seal", session: sessionId, count: last.seq + 1, head: last.hash });
    return { file, lines: out, keys, last };
  });
}

export function append(ev, dir = DATA, now) {
  const keys = loadKeys(dir);
  const first = !fs.existsSync(path.join(dir, "records", safeId(ev.session_id) + ".jsonl"));
  let admission = null;
  if (first) { try { admission = loadAdmission(ev.cwd); } catch (e) { logError(e); } }
  return appendDesc(ev.session_id, describe(ev, keys.fk, null), ev.hook_event_name === "PreToolUse" ? touchedBy(ev) : null, { dir, admission, now });
}

// Which outside parties see the head after this append.
//   Witnesses (HIVE_WITNESS_URL, comma separated): at the start, before every tool call runs, and at every seal.
//   Timestamp authorities (HIVE_TSA_URL, comma separated, RFC 3161): at the start and at every seal.
const list = v => String(v).split(",").map(x => x.trim()).filter(x => x && x !== "off");
export function outsideJob(r) {
  const evs = r.lines.map(l => l.event);
  const start = evs.includes("RecorderKey"), seal = evs.includes("Seal"), pre = evs.includes("PreToolUse");
  if (!start && !seal && !pre) return null;
  const witnesses = list(process.env.HIVE_WITNESS_URL ?? "https://witness.thehiveryiq.com/v1/witness");
  const tsas = (start || seal) ? list(process.env.HIVE_TSA_URL ?? "http://timestamp.digicert.com") : [];
  if (!witnesses.length && !tsas.length) return null;
  const req = { recorder_key: r.keys.pub, session_fp: sha256hex(String(r.last.session)), count: r.last.seq + 1, head: r.last.hash };
  // Signed with the recorder key, so the witness remembers it and nobody else can add to this session.
  req.req_sig = b64u(crypto.sign(null, Buffer.from(canon({ count: req.count, head: req.head, recorder_key: req.recorder_key, session_fp: req.session_fp })), r.keys.sk));
  return { base: r.file.replace(/\.jsonl$/, ""), req, witnesses, tsas };
}

// Detached by default, so a slow or offline witness never holds up Claude Code.
// HIVE_WITNESS_WAIT_MS > 0 waits up to that long for the statements before the hook returns,
// so they exist before the tool call runs. It still never blocks or fails the call.
export async function sendOutside(job) {
  if (!job) return;
  const wait = Number(process.env.HIVE_WITNESS_WAIT_MS || 0);
  if (wait > 0) {
    const { sendAll } = await import("./witness-client.mjs");
    const done = await Promise.race([sendAll({ ...job, timeoutMs: wait, tries: 1 }).then(() => true), new Promise(r => setTimeout(() => r(false), wait))]);
    if (done && !missing(job)) return;
    // Slow or asleep: keep trying in the background so the statement still arrives, late and marked by its own time.
  }
  const rest = wait > 0 ? { ...job, witnesses: missing(job) || [], tsas: job.tsas.filter(u => !haveTs(job, u)) } : job;
  if (!rest.witnesses.length && !rest.tsas.length) return;
  const child = spawn(process.execPath, [path.join(HERE, "witness-client.mjs"), JSON.stringify(rest)], { detached: true, stdio: "ignore" });
  child.unref();
}
// Which witnesses have not yet answered for this head.
function linesOf(f) { try { return fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)); } catch { return []; } }
function missing(job) {
  const got = linesOf(job.base + ".witness.jsonl").filter(w => w.count === job.req.count && w.head === job.req.head).length;
  return got >= job.witnesses.length ? null : job.witnesses;
}
function haveTs(job, url) { return linesOf(job.base + ".timestamps.jsonl").some(t => t.count === job.req.count && t.head === job.req.head && t.tsa === url); }

// Service mode: HIVE_RECORDER_URL points at recorderd, run by whoever starts the agent, somewhere the
// agent can't read. The hook keeps only the fingerprint key; it sends fingerprints and touched
// paths and hosts, never content. The agent can add lines through the hook. It can't change,
// reorder or remove one, because it never holds the signing keys or the record.
async function sendToService(ev) {
  const fk = loadFingerprintKey();
  const body = JSON.stringify({ session_id: ev.session_id, desc: describe(ev, fk, null), touched: ev.hook_event_name === "PreToolUse" ? touchedBy(ev) : null });
  try {
    const r = await fetch(process.env.HIVE_RECORDER_URL.replace(/\/$/, "") + "/v1/event", { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(Number(process.env.HIVE_RECORDER_TIMEOUT_MS || 3000)) });
    if (!r.ok) throw new Error("recorderd HTTP " + r.status);
  } catch (e) { logError(e); }
}
function loadFingerprintKey(dir = DATA) {
  const kd = path.join(dir, "keys"); fs.mkdirSync(kd, { recursive: true, mode: 0o700 });
  const f = path.join(kd, "fingerprint.key");
  if (!fs.existsSync(f)) { const tmp = f + "." + process.pid; fs.writeFileSync(tmp, crypto.randomBytes(32).toString("hex"), { mode: 0o600 }); try { fs.linkSync(tmp, f); } catch {} fs.unlinkSync(tmp); }
  return Buffer.from(fs.readFileSync(f, "utf8").trim(), "hex");
}

async function main() {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  const ev = JSON.parse(raw);
  if (process.env.HIVE_RECORDER_URL) return sendToService(ev);
  await sendOutside(outsideJob(append(ev)));
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch(logError).finally(() => { process.exitCode = 0; });
}
