#!/usr/bin/env node
// Check a hive.agent-action/1 record offline. Node 20 or later, no dependencies.
//
//   node verify.mjs <session.jsonl> [--key <key.json | public key>] [--witness <file>] [--witness-key <key>]...
//                   [--min-witnesses <n>] [--max-lag <seconds>] [--require-witness] [--full-coverage]
//                   [--timestamps <file>] [--require-timestamp] [--admission <policy.json>] [--json]
//   --ask-witness [url] fetches every statement the witness remembers for this session (default
//   https://witness.thehiveryiq.com) and checks the record against all of them. It fails if the
//   witness doesn't remember the session.
//   --strict turns on --require-witness --full-coverage --require-timestamp --require-end and --max-lag 10.
//   --witness-key can be given more than once. --min-witnesses counts different pinned witnesses.
//   Timestamp tokens (RFC 3161) are checked with the openssl command and your system's CA certificates.
//   --disclose-for <vendor> checks a copy made for one vendor: other lines may be digest only, that vendor's may not.
//   node verify.mjs disclose <session.jsonl> --vendor <name> --out <copy.jsonl>
//   node verify.mjs answer <session.jsonl> --text <answer.txt>     (does this answer, and its trail, match the record?)
//   node verify.mjs statement <statement.json> <copy.jsonl>... [--ask-witness url] [--key key.json] [--vendor-key key]
//   node verify.mjs reveal <session.jsonl> --seq <n> --field <input|response|error|prompt|last_message> --value <file> --fingerprint-key <file>
//
// Exit code 0: every gate passes and nothing fell outside the admission.
//           3: every gate passes, and one or more calls fell outside the signed admission.
//           1: a gate failed. The record was changed, or is not what you were told it is.
import fs from "node:fs";
import crypto from "node:crypto";
import { verifyRecord, canon, GATES, scopeOf, discloseFor, checkAnswer, checkStatement } from "./core.mjs";
import { ml_dsa65 } from "./vendor/ml-dsa-65.mjs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const c = {
  sha256hex: s => crypto.createHash("sha256").update(s).digest("hex"),
  verify: (pub, msg, sig) => {
    try { return crypto.verify(null, Buffer.from(msg), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub }, format: "jwk" }), Buffer.from(sig, "base64url")); }
    catch { return false; }
  },
  verifyPq: (pub, msg, sig) => {
    try { return ml_dsa65.verify(Buffer.from(sig, "base64url"), Buffer.from(msg), Buffer.from(pub, "base64url")); }
    catch { return false; }
  },
};

const readLines = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const keyArg = v => { if (!v) return undefined; if (fs.existsSync(v)) { const j = JSON.parse(fs.readFileSync(v, "utf8")); return j.public_key || j.witness_key; } return v; };
function opt(args, name) { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; }
function opts(args, name) { return args.flatMap((a, i) => a === name && args[i + 1] ? [args[i + 1]] : []); }
const FLAGS = new Set(["--ask-witness", "--json", "--require-witness", "--full-coverage", "--require-timestamp", "--require-end", "--strict"]);

// Check RFC 3161 timestamp tokens with openssl: the token must be signed by a TSA certificate that
// chains to a CA your system trusts, and must cover exactly this head hash.
const CA_FILES = ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem", "/opt/homebrew/etc/openssl@3/cert.pem", "/usr/local/etc/openssl@3/cert.pem"];
export function checkTimestamps(entries, caFile) {
  const ca = caFile || CA_FILES.find(f => fs.existsSync(f));
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hive-tsa-"));
  try {
    return entries.map((t, i) => {
      const f = path.join(tmp, i + ".tsr");
      fs.writeFileSync(f, Buffer.from(t.token, "base64"));
      if (!ca) return { ...t, ok: false, why: "no CA certificate bundle found; pass --ca-file" };
      const v = spawnSync("openssl", ["ts", "-verify", "-digest", t.head, "-in", f, "-CAfile", ca], { encoding: "utf8" });
      if (v.error) return { ...t, ok: false, why: "openssl is not installed" };
      const ok = /Verification: OK/.test(v.stdout + v.stderr);
      const txt = spawnSync("openssl", ["ts", "-reply", "-in", f, "-text"], { encoding: "utf8" }).stdout || "";
      const m = txt.match(/Time stamp: (.+)/);
      return { ...t, ok, why: ok ? undefined : (v.stderr || v.stdout).trim().split("\n").pop(), gen_time: m ? new Date(m[1]).toISOString() : undefined };
    });
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

// Ask a witness for every statement it remembers for this record's recorder key and session.
export async function fetchMemory(lines, witnessUrl) {
  const base = String(witnessUrl).replace(/\/v1\/witness\/?$/, "").replace(/\/$/, "");
  const first = lines[0] || {};
  const q = new URLSearchParams({ recorder_key: first.public_key || "", session_fp: c.sha256hex(String(first.session || "")) });
  const r = await fetch(base + "/v1/witness/statements?" + q, { signal: AbortSignal.timeout(90000) });
  if (!r.ok) throw new Error("the witness at " + base + " answered " + r.status + ": " + (await r.text()).slice(0, 120));
  return { statements: (await r.json()).statements, from: base };
}

export function verifyFile(file, { key, witness, witnessKey, witnessKeys, minWitnesses, maxLag, requireWitness, fullCoverage, timestamps, requireTimestamp, requireEnd, caFile, admission, memory, requireMemory, disclose } = {}) {
  const lines = readLines(file);
  const wf = witness || file.replace(/\.jsonl$/, ".witness.jsonl");
  const witnesses = fs.existsSync(wf) && wf !== file ? readLines(wf) : [];
  const tf = timestamps || file.replace(/\.jsonl$/, ".timestamps.jsonl");
  const ts = fs.existsSync(tf) && tf !== file ? checkTimestamps(readLines(tf), caFile) : [];
  const pol = admission ? JSON.parse(fs.readFileSync(admission, "utf8")) : null;
  const pins = [...(witnessKeys || []), ...(witnessKey ? [witnessKey] : [])].map(keyArg);
  return verifyRecord(lines, c, {
    pin: keyArg(key), witnesses, witnessPins: pins, minWitnesses, maxLagSec: maxLag, requireWitness, requireFullCoverage: fullCoverage,
    timestamps: ts, requireTimestamp, requireEnd, memory, requireMemory, ...(disclose ? { allowRedacted: true, discloseFor: disclose } : {}),
    admissionPin: pol ? c.sha256hex(canon(pol)) : undefined, admissionScope: pol ? scopeOf(pol) : undefined,
  });
}

function reveal(args) {
  const file = args[1], seq = Number(opt(args, "--seq")), field = opt(args, "--field");
  const value = JSON.parse(fs.readFileSync(opt(args, "--value"), "utf8"));
  const fk = Buffer.from(fs.readFileSync(opt(args, "--fingerprint-key"), "utf8").trim(), "hex");
  const line = readLines(file)[seq];
  const got = crypto.createHmac("sha256", fk).update(canon(value)).digest("hex");
  const want = line && line.fp && line.fp[field];
  const ok = !!want && got === want;
  console.log(ok ? `MATCH  line ${seq} ${field}: the value you supplied is what the record fingerprinted.` : `NO MATCH  line ${seq} ${field}: the value you supplied is not what the record fingerprinted.`);
  process.exitCode = ok ? 0 : 1;
}

// Every session the witness remembers for a recorder key in a period.
export async function fetchSessions(recorderKey, period, witnessUrl) {
  const base = String(witnessUrl).replace(/\/v1\/witness\/?$/, "").replace(/\/$/, "");
  const r = await fetch(base + "/v1/witness/sessions?" + new URLSearchParams({ recorder_key: recorderKey, from: period.from, to: period.to }), { signal: AbortSignal.timeout(90000) });
  if (!r.ok) throw new Error("the witness at " + base + " answered " + r.status);
  return (await r.json()).sessions;
}
async function statementCmd(args) {
  const st = JSON.parse(fs.readFileSync(args[1], "utf8"));
  const files = args.slice(2).filter((a, i, all) => !a.startsWith("--") && !/^https?:/.test(a) && !(i > 0 && all[i - 1].startsWith("--") && all[i - 1] !== "--ask-witness"));
  const discs = files.map(readLines);
  const nx = args[args.indexOf("--ask-witness") + 1];
  const url = nx && /^https?:/.test(nx) ? nx : "https://witness.thehiveryiq.com";
  const memory = {};
  for (const L of discs) memory[c.sha256hex(String(L[0].session))] = (await fetchMemory(L, url)).statements;
  const witnessSessions = await fetchSessions(st.recorder_key, st.period, url);
  const r = checkStatement(st, discs, c, { recorderPin: keyArg(opt(args, "--key")), vendorPin: keyArg(opt(args, "--vendor-key")), witnessPin: keyArg(opt(args, "--witness-key")), memory, witnessSessions, from: url });
  if (r.ok) console.log(`PASS   ${st.vendor}: ${r.sessions} sessions, ${r.asked} pulls, ${r.outside} outside the entitlement, ${r.answers} answers drew on its data. Every session the witness saw in the period is included.${r.accepted_at ? " Accepted by the vendor at " + r.accepted_at + "." : ""}`);
  else console.log(`REJECT ${r.step}: ${r.why}`);
  process.exitCode = r.ok ? 0 : 1;
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === "reveal") return reveal(args);
  if (args[0] === "disclose") { const out = discloseFor(readLines(args[1]), opt(args, "--vendor"), c.sha256hex); fs.writeFileSync(opt(args, "--out"), out.map(l => JSON.stringify(l)).join("\n") + "\n"); console.log(`wrote ${opt(args, "--out")}: ${out.filter(l => l.redacted).length} of ${out.length} lines digest only`); return; }
  if (args[0] === "answer") { const r = checkAnswer(readLines(args[1]), fs.readFileSync(opt(args, "--text"), "utf8"), c); console.log(r.ok ? `MATCH  the answer at line ${r.stop_seq} drew on ${r.drew_on.map(d => "line " + d.seq + " (" + (d.vendor || "no vendor") + ", " + d.matched + " figures)").join(", ") || "no tool results"}` : "NO MATCH  " + r.why); process.exitCode = r.ok ? 0 : 1; return; }
  if (args[0] === "statement") return statementCmd(args);
  const files = args.filter((a, i) => !a.startsWith("--") && !/^https?:\/\//.test(a) && !(i > 0 && args[i - 1].startsWith("--") && !FLAGS.has(args[i - 1])));
  if (!files.length) { console.log("usage: node verify.mjs <session.jsonl> [--key key.json] [--witness-key key]... [--min-witnesses n] [--max-lag s] [--require-witness] [--full-coverage] [--require-timestamp] [--require-end] [--strict] [--admission policy.json] [--json]"); process.exitCode = 2; return; }
  let bad = 0, outside = 0;
  for (const f of files) {
    let r;
    try {
      let memory, requireMemory;
      if (args.includes("--ask-witness")) {
        const nx = args[args.indexOf("--ask-witness") + 1];
        const url = nx && /^https?:/.test(nx) ? nx : "https://witness.thehiveryiq.com";
        memory = await fetchMemory(readLines(f), url); requireMemory = true;
      }
      r = verifyFile(f, { memory, requireMemory,
      key: opt(args, "--key"), witness: opt(args, "--witness"), witnessKeys: opts(args, "--witness-key"),
      minWitnesses: opt(args, "--min-witnesses") ? Number(opt(args, "--min-witnesses")) : undefined,
      maxLag: opt(args, "--max-lag") ? Number(opt(args, "--max-lag")) : args.includes("--strict") ? 10 : undefined,
      requireWitness: args.includes("--require-witness") || args.includes("--strict"), fullCoverage: args.includes("--full-coverage") || args.includes("--strict"),
      timestamps: opt(args, "--timestamps"), requireTimestamp: args.includes("--require-timestamp") || args.includes("--strict"), caFile: opt(args, "--ca-file"),
      requireEnd: args.includes("--require-end") || args.includes("--strict"),
      admission: opt(args, "--admission"), disclose: opt(args, "--disclose-for"),
    });  }
    catch (e) { r = { ok: false, gates: { FORMAT: "FAIL" }, first_failure: { gate: "FORMAT", why: String(e.message) } }; }
    if (!r.ok) bad++;
    else if (r.summary && r.summary.outside_admission.length) outside++;
    if (args.includes("--json")) { console.log(JSON.stringify({ file: f, ...r })); continue; }
    console.log(`${r.ok ? "PASS  " : "REJECT"} ${f}`);
    console.log("  " + GATES.map(g => `${g} ${r.gates[g] || "-"}`).join("  "));
    if (r.first_failure) console.log(`  first failure: ${r.first_failure.gate}, ${r.first_failure.why}`);
    if (r.ok && r.summary) {
      const s = r.summary;
      console.log(`  ${r.entries} lines, ${r.sealed ? "sealed" : "open tail of " + r.open_tail + " lines"}, witnessed ${r.witnessed.length} time(s) by ${r.witness_coverage.witnesses} witness(es), last ${r.witness_coverage.unwitnessed_tail} line(s) unwitnessed, slowest witness ${r.witness_coverage.max_lag_s} s`);
      if (r.witness_memory) console.log(`  the witness at ${r.witness_memory.from} remembers ${r.witness_memory.remembered} statement(s) for this session, up to line ${r.witness_memory.max_count - 1}, and every one holds`);
      if (r.timestamps.length) console.log(`  public timestamps: ${r.timestamps.map(t => "line " + (t.count - 1) + " at " + t.at + " by " + t.tsa).join("; ")}`);
      console.log(`  prompts ${s.prompts}, turns ${s.turns}, tool calls asked ${s.tool_calls_asked}, completed ${s.tool_calls_completed}, failed ${s.tool_calls_failed}, asked with no outcome ${s.asked_without_outcome.length}`);
      console.log(`  tools completed: ${Object.entries(s.tools_completed).map(([k, v]) => k + " " + v).join(", ") || "none"}`);
      if (s.admission) {
        console.log(`  admission: tools ${s.admission.scope.tools.join(" ")} | paths ${s.admission.scope.paths.join(" ")} | hosts ${s.admission.scope.hosts.join(" ") || "none"}${s.admission.scope.datasets ? " | datasets " + (s.admission.scope.datasets.join(" ") || "none") : ""}`);
        if (!s.outside_admission.length) console.log("  every tool call stayed inside the admission");
        for (const o of s.outside_admission) {
          const what = [o.outside.tool ? "tool " + o.tool : "", o.outside.hosts.length ? "hosts " + o.outside.hosts.join(", ") : "", o.outside.paths.length ? "paths " + o.outside.paths.join(", ") : "", o.outside.datasets && o.outside.datasets.length ? "datasets " + o.outside.datasets.join(", ") : ""].filter(Boolean).join("; ");
          console.log(`  OUTSIDE ADMISSION  line ${o.seq} ${o.tool}: ${what}. ${o.failed ? "It ran and failed." : o.ran ? "It ran." : "It did not run."}`);
        }
      }
    }
  }
  process.exitCode = bad ? 1 : outside ? 3 : 0;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();
