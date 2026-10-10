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
import { FORMAT, ZERO, canon } from "./core.mjs";

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
  return { sk, pub: raw, keyId, fk: Buffer.from(fs.readFileSync(fkPath, "utf8").trim(), "hex") };
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
export function describe(ev, fk) {
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
  if (e === "PreToolUse") take("input", ev.tool_input);
  else if (e === "PostToolUse") { take("input", ev.tool_input); take("response", ev.tool_response); }
  else if (e === "PostToolUseFailure") { take("input", ev.tool_input); take("error", ev.error); if (ev.is_interrupt !== undefined) d.interrupted = !!ev.is_interrupt; }
  else if (e === "UserPromptSubmit") take("prompt", ev.prompt);
  else if (e === "Stop" || e === "SubagentStop") take("last_message", ev.last_assistant_message);
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

export function append(ev, dir = DATA, now = () => new Date().toISOString()) {
  const keys = loadKeys(dir);
  const rd = path.join(dir, "records"); fs.mkdirSync(rd, { recursive: true });
  const file = path.join(rd, safeId(ev.session_id) + ".jsonl");
  return withLock(file, () => {
    const out = [];
    let last = lastLine(file);
    const write = b => {
      const line = { v: FORMAT, seq: last ? last.seq + 1 : 0, prev: last ? last.hash : ZERO, t: now(), key: keys.keyId, ...b };
      const c = canon(line);
      line.hash = sha256hex(c);
      line.sig = b64u(crypto.sign(null, Buffer.from(c), keys.sk));
      fs.appendFileSync(file, JSON.stringify(line) + "\n");
      out.push(line); last = line;
    };
    if (!last) write({ event: "RecorderKey", session: ev.session_id, public_key: keys.pub, key_id: keys.keyId, recorder: "hive-recorder/1.0.0" });
    write(describe(ev, keys.fk));
    // Seal at the end of each turn and at session end.
    if (ev.hook_event_name === "Stop" || ev.hook_event_name === "SessionEnd") write({ event: "Seal", session: ev.session_id, count: last.seq + 1, head: last.hash });
    return { file, lines: out, keys };
  });
}

// Send the latest seal head (fingerprints only) to the witness in a detached process,
// so a slow or offline witness never holds up Claude Code.
function witnessLater(file, seal, keys) {
  const url = process.env.HIVE_WITNESS_URL ?? "https://witness.thehiveryiq.com/v1/witness";
  if (!url || url === "off") return;
  const req = { recorder_key: keys.pub, session_fp: sha256hex(String(seal.session)), count: seal.count, head: seal.head };
  const child = spawn(process.execPath, [path.join(HERE, "witness-client.mjs"), url, file.replace(/\.jsonl$/, ".witness.jsonl"), JSON.stringify(req)], { detached: true, stdio: "ignore" });
  child.unref();
}

async function main() {
  let raw = "";
  for await (const chunk of process.stdin) raw += chunk;
  const ev = JSON.parse(raw);
  const r = append(ev);
  const seal = r.lines.find(l => l.event === "Seal");
  if (seal) witnessLater(r.file, seal, r.keys);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch(logError).finally(() => { process.exitCode = 0; });
}
