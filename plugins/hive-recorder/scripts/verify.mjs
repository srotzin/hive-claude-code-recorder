#!/usr/bin/env node
// Check a hive.agent-action/1 record offline. Node 20 or later, no dependencies.
//
//   node verify.mjs <session.jsonl> [--key <key.json | public key>] [--witness <file>] [--witness-key <key>] [--admission <policy.json>] [--json]
//   node verify.mjs reveal <session.jsonl> --seq <n> --field <input|response|error|prompt|last_message> --value <file> --fingerprint-key <file>
//
// Exit code 0: every gate passes and nothing fell outside the admission.
//           3: every gate passes, and one or more calls fell outside the signed admission.
//           1: a gate failed. The record was changed, or is not what you were told it is.
import fs from "node:fs";
import crypto from "node:crypto";
import { verifyRecord, canon, GATES } from "./core.mjs";
import { ml_dsa65 } from "./vendor/ml-dsa-65.mjs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const c = {
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

export function verifyFile(file, { key, witness, witnessKey, admission } = {}) {
  const lines = readLines(file);
  const wf = witness || file.replace(/\.jsonl$/, ".witness.jsonl");
  const witnesses = fs.existsSync(wf) && wf !== file ? readLines(wf) : [];
  const admissionPin = admission ? c.sha256hex(canon(JSON.parse(fs.readFileSync(admission, "utf8")))) : undefined;
  return verifyRecord(lines, c, { pin: keyArg(key), witnesses, witnessPin: keyArg(witnessKey), admissionPin });
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

function main() {
  const args = process.argv.slice(2);
  if (args[0] === "reveal") return reveal(args);
  const files = args.filter((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--")));
  if (!files.length) { console.log("usage: node verify.mjs <session.jsonl> [--key key.json] [--witness file] [--witness-key key] [--json]"); process.exitCode = 2; return; }
  let bad = 0, outside = 0;
  for (const f of files) {
    let r;
    try { r = verifyFile(f, { key: opt(args, "--key"), witness: opt(args, "--witness"), witnessKey: opt(args, "--witness-key"), admission: opt(args, "--admission") }); }
    catch (e) { r = { ok: false, gates: { FORMAT: "FAIL" }, first_failure: { gate: "FORMAT", why: String(e.message) } }; }
    if (!r.ok) bad++;
    else if (r.summary && r.summary.outside_admission.length) outside++;
    if (args.includes("--json")) { console.log(JSON.stringify({ file: f, ...r })); continue; }
    console.log(`${r.ok ? "PASS  " : "REJECT"} ${f}`);
    console.log("  " + GATES.map(g => `${g} ${r.gates[g] || "-"}`).join("  "));
    if (r.first_failure) console.log(`  first failure: ${r.first_failure.gate}, ${r.first_failure.why}`);
    if (r.ok && r.summary) {
      const s = r.summary;
      console.log(`  ${r.entries} lines, ${r.sealed ? "sealed" : "open tail of " + r.open_tail + " lines"}, witnessed ${r.witnessed.length} time(s)`);
      console.log(`  prompts ${s.prompts}, turns ${s.turns}, tool calls asked ${s.tool_calls_asked}, completed ${s.tool_calls_completed}, failed ${s.tool_calls_failed}, asked with no outcome ${s.asked_without_outcome.length}`);
      console.log(`  tools completed: ${Object.entries(s.tools_completed).map(([k, v]) => k + " " + v).join(", ") || "none"}`);
      if (s.admission) {
        console.log(`  admission: tools ${s.admission.scope.tools.join(" ")} | paths ${s.admission.scope.paths.join(" ")} | hosts ${s.admission.scope.hosts.join(" ") || "none"}`);
        if (!s.outside_admission.length) console.log("  every tool call stayed inside the admission");
        for (const o of s.outside_admission) {
          const what = [o.outside.tool ? "tool " + o.tool : "", o.outside.hosts.length ? "hosts " + o.outside.hosts.join(", ") : "", o.outside.paths.length ? "paths " + o.outside.paths.join(", ") : ""].filter(Boolean).join("; ");
          console.log(`  OUTSIDE ADMISSION  line ${o.seq} ${o.tool}: ${what}. ${o.ran ? "It ran." : "It did not run."}`);
        }
      }
    }
  }
  process.exitCode = bad ? 1 : outside ? 3 : 0;
}
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) main();
