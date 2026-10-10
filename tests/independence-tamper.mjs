// Tamper cases aimed at the v1.2 protections, built from a real recorderd session.
//   node tests/independence-tamper.mjs <session.jsonl> <keys dir> <policy.json> <out dir> <witness key> [witness url]
// Checked the strict way a reviewer should: verify.mjs --strict.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { canon, body } from "../plugins/hive-recorder/scripts/core.mjs";
import { verifyFile } from "../plugins/hive-recorder/scripts/verify.mjs";
import { ml_dsa65 } from "../plugins/hive-recorder/scripts/vendor/ml-dsa-65.mjs";

const [src, keys, policy, out, wkey, wurl = "https://witness.thehiveryiq.com/v1/witness"] = process.argv.slice(2);
const rd = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const base = rd(src), wit = rd(src.replace(/\.jsonl$/, ".witness.jsonl")), tsa = rd(src.replace(/\.jsonl$/, ".timestamps.jsonl"));
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
const iEsc = base.findIndex(l => l.event === "PreToolUse" && l.scope && l.scope.outside.hosts.length);
const escId = base[iEsc].tool.use_id;
const noEsc = rebuild(base.filter(l => !(l.tool && l.tool.use_id === escId)));
// Ask the witness again, now, for every head of the rebuilt record: what a lab could do after the fact.
async function freshStatements(lines) {
  const req = l => ({ recorder_key: lines[0].public_key, session_fp: H(String(l.session)), count: l.seq + 1, head: l.hash });
  const pick = lines.filter(l => ["SessionStart", "PreToolUse", "Seal"].includes(l.event));
  const outS = [];
  for (const l of pick) { const r = await fetch(wurl, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(req(l)) }); outS.push(await r.json()); }
  return outS;
}
const cases = [
  ["escape-deleted-resigned", "The Hugging Face call is deleted and every line re-signed with both of the recorder's keys. The original witness statements are kept.", "WITNESS", async () => ({ lines: noEsc, wit, tsa: [] })],
  ["statements-withheld", "The same rewrite, handed over without any witness statements.", "WITNESS", async () => ({ lines: noEsc, wit: [], tsa: [] })],
  ["fresh-statements-later", "The same rewrite, with brand new witness statements requested from the witness afterwards.", "WITNESS", async () => ({ lines: noEsc, wit: await freshStatements(noEsc), tsa: [] })],
  ["timestamps-withheld", "The record and witness statements untouched, the public timestamps left out.", "TIMESTAMP", async () => ({ lines: base, wit, tsa: [] })],
  ["timestamp-moved", "A DigiCert token is relabelled to cover a different line.", "TIMESTAMP", async () => ({ lines: base, wit, tsa: tsa.map((t, i) => i === 0 ? { ...t, count: t.count + 1, head: base[t.count].hash } : t) })],
  ["tail-dropped", "The last seal and session end are cut off, so the end of the session is not shown.", "SEAL", async () => ({ lines: base.slice(0, base.length - 2), wit: wit.filter(w => w.count <= base.length - 2), tsa: tsa.filter(t => t.count <= base.length - 2) })],
];
fs.mkdirSync(out, { recursive: true });
const manifest = []; let n = 0;
for (const [id, what, expected, make] of cases) {
  const m = await make(), f = path.join(out, id + ".jsonl");
  const w = l => l.map(x => JSON.stringify(x)).join("\n") + (l.length ? "\n" : "");
  fs.writeFileSync(f, w(m.lines)); fs.writeFileSync(f.replace(/\.jsonl$/, ".witness.jsonl"), w(m.wit)); fs.writeFileSync(f.replace(/\.jsonl$/, ".timestamps.jsonl"), w(m.tsa));
  const r = verifyFile(f, { key: base[0].public_key, witnessKey: wkey, admission: policy, requireWitness: true, fullCoverage: true, maxLag: 10, requireTimestamp: true, requireEnd: true });
  const got = r.first_failure && r.first_failure.gate, ok = !r.ok && got === expected;
  if (ok) n++;
  manifest.push({ id, file: id + ".jsonl", what, expected, got, why: r.first_failure && r.first_failure.why });
  console.log((ok ? "ok   " : "FAIL ") + id + "  " + (got || "accepted") + (r.first_failure ? ", " + r.first_failure.why : ""));
}
fs.writeFileSync(path.join(out, "MANIFEST.json"), JSON.stringify(manifest, null, 2));
console.log(`\n${n} of ${cases.length} rejected at the expected gate.`);
process.exitCode = n === cases.length ? 0 : 1;
