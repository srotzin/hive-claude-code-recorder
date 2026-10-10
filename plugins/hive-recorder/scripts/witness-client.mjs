#!/usr/bin/env node
// Detached helper: sends one seal head to the witness and saves the signed statement.
// Only fingerprints leave the machine: recorder public key, a hash of the session id,
// the line count and the head hash. Failures are logged and never retried forever.
import fs from "node:fs";
const [url, out, body] = process.argv.slice(2);
const sleep = ms => new Promise(r => setTimeout(r, ms));
for (let i = 0; i < 4; i++) {
  try {
    const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body, signal: AbortSignal.timeout(60000) });
    if (r.ok) { const j = await r.json(); fs.appendFileSync(out, JSON.stringify(j) + "\n"); process.exit(0); }
    if (r.status >= 400 && r.status < 500) break;
  } catch {}
  await sleep(2000 * (i + 1));
}
try { fs.appendFileSync(out.replace(/\.witness\.jsonl$/, ".witness-errors.log"), new Date().toISOString() + " witness unreachable " + url + "\n"); } catch {}
