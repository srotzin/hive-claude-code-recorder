#!/usr/bin/env node
// Sends one record head to every configured witness and timestamp authority, and saves what comes back.
// Only fingerprints leave the machine: the recorder public key, a hash of the session id,
// the line count and the head hash. A timestamp authority gets the head hash alone.
// Failures are logged. Nothing here can hold up or change a tool call.
import fs from "node:fs";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const sleep = ms => new Promise(r => setTimeout(r, ms));
const logErr = (base, msg) => { try { fs.appendFileSync(base + ".witness-errors.log", new Date().toISOString() + " " + msg + "\n"); } catch {} };

// DER for an RFC 3161 TimeStampReq over a SHA-256 digest, asking for the TSA certificate.
function der(tag, body) {
  const n = body.length;
  const len = n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
}
export function tsaRequest(headHex) {
  const alg = der(0x30, Buffer.concat([der(0x06, Buffer.from("608648016503040201", "hex")), Buffer.from([0x05, 0x00])]));
  const imprint = der(0x30, Buffer.concat([alg, der(0x04, Buffer.from(headHex, "hex"))]));
  let nonce = crypto.randomBytes(8); nonce[0] &= 0x7f; if (!nonce[0]) nonce[0] = 1;
  return der(0x30, Buffer.concat([der(0x02, Buffer.from([1])), imprint, der(0x02, nonce), der(0x01, Buffer.from([0xff]))]));
}

async function post(url, body, type, timeoutMs) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": type }, body, signal: AbortSignal.timeout(timeoutMs) });
  if (!r.ok) { const e = new Error("HTTP " + r.status); e.status = r.status; throw e; }
  return type === "application/json" ? r.json() : Buffer.from(await r.arrayBuffer());
}

async function tryHard(fn, tries, base, what) {
  for (let i = 0; i < tries; i++) {
    try { return await fn(); } catch (e) { if (e.status >= 400 && e.status < 500) break; if (i < tries - 1) await sleep(1500 * (i + 1)); }
  }
  logErr(base, what + " unreachable");
  return null;
}

// job: { base: record path without .jsonl, req: { recorder_key, session_fp, count, head },
//        witnesses: [url], tsas: [url], timeoutMs, tries }
export async function sendAll(job) {
  const { base, req, witnesses = [], tsas = [], timeoutMs = 60000, tries = 4 } = job;
  const body = JSON.stringify(req);
  await Promise.all([
    ...witnesses.map(async url => {
      const st = await tryHard(() => post(url, body, "application/json", timeoutMs), tries, base, "witness " + url);
      if (st) fs.appendFileSync(base + ".witness.jsonl", JSON.stringify(st) + "\n");
    }),
    ...tsas.map(async url => {
      const tok = await tryHard(() => post(url, tsaRequest(req.head), "application/timestamp-query", timeoutMs), tries, base, "timestamp authority " + url);
      if (tok) fs.appendFileSync(base + ".timestamps.jsonl", JSON.stringify({ v: "hive.agent-action-timestamp/1", count: req.count, head: req.head, tsa: url, token: tok.toString("base64") }) + "\n");
    }),
  ]);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  sendAll(JSON.parse(process.argv[2])).catch(() => {}).finally(() => process.exit(0));
}
