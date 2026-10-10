// Tamper cases checked against what the live witness remembers. No witness statements are handed over
// with any of them: the reviewer asks the witness directly. Nothing is sent to the witness.
//   node tests/memory-tamper.mjs <session.jsonl> <keys dir> <policy.json> <out dir> [witness url]
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { canon, body } from "../plugins/hive-recorder/scripts/core.mjs";
import { verifyFile, fetchMemory } from "../plugins/hive-recorder/scripts/verify.mjs";
import { ml_dsa65 } from "../plugins/hive-recorder/scripts/vendor/ml-dsa-65.mjs";

const [src, keys, policy, out, wurl = "https://witness.thehiveryiq.com"] = process.argv.slice(2);
const base = fs.readFileSync(src, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const sk = crypto.createPrivateKey(fs.readFileSync(path.join(keys, "recorder-ed25519.pem")));
const pq = ml_dsa65.keygen(Uint8Array.from(Buffer.from(fs.readFileSync(path.join(keys, "recorder-ml-dsa-65.seed"), "utf8").trim(), "hex")));
const H = s => crypto.createHash("sha256").update(s).digest("hex");
function rebuild(lines) {
  let prev = "0".repeat(64);
  return lines.map((l0, i) => {
    const l = { ...body(l0), seq: i, prev };
    if (l.event === "Seal") { l.count = i; l.head = prev; }
    const c = canon(l), h = H(c); prev = h;
    return { ...l, hash: h, sig: crypto.sign(null, Buffer.from(c), sk).toString("base64url"), sig_pq: Buffer.from(ml_dsa65.sign(Buffer.from(c), pq.secretKey)).toString("base64url") };
  });
}
const iOut = base.findIndex(l => l.event === "PreToolUse" && l.scope && l.scope.outside.datasets && l.scope.outside.datasets.length);
const id = base[iOut].tool.use_id;
const cases = [
  ["pull-deleted", "The mortgage pull is deleted and every line re-signed with both of the recorder's own keys. No witness statements are handed over.", "WITNESS",
    () => rebuild(base.filter(l => !(l.tool && l.tool.use_id === id)))],
  ["pull-relabelled", "The mortgage pull is relabelled as a WTI futures pull, inside the admission, and every line re-signed.", "WITNESS",
    () => rebuild(base.map(l => l.seq === iOut ? { ...l, scope: { touched: { ...l.scope.touched, datasets: ["futures.wti.eod"] }, outside: { ...l.scope.outside, datasets: [] } } } : l))],
  ["end-cut", "The record is cut off right after the Brent pull, before the mortgage pull. The signatures are untouched.", "WITNESS",
    () => base.slice(0, iOut)],
];
const memory = await fetchMemory(base, wurl);
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, "witness-memory.json"), JSON.stringify(memory, null, 1));
const manifest = []; let n = 0;
for (const [cid, what, expected, make] of cases) {
  const f = path.join(out, cid + ".jsonl");
  fs.writeFileSync(f, make().map(x => JSON.stringify(x)).join("\n") + "\n");
  const r = verifyFile(f, { key: base[0].public_key, witness: f + ".none", timestamps: f + ".none", admission: policy, memory, requireMemory: true });
  const got = r.first_failure && r.first_failure.gate, ok = !r.ok && got === expected;
  if (ok) n++;
  manifest.push({ id: cid, file: cid + ".jsonl", what, expected, got, why: r.first_failure && r.first_failure.why });
  console.log((ok ? "ok   " : "FAIL ") + cid + "  " + (got || "accepted") + (r.first_failure ? ", " + r.first_failure.why : ""));
}
fs.writeFileSync(path.join(out, "MANIFEST.json"), JSON.stringify(manifest, null, 2));
console.log(`\n${n} of ${cases.length} rejected at the expected gate.`);
process.exitCode = n === cases.length ? 0 : 1;
