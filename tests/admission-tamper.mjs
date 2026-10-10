// Build tamper cases from a real recorded session that has an admission and ML-DSA-65 signatures.
//   node tests/admission-tamper.mjs <session.jsonl> <keys dir> <policy.json> <out dir> <witness key>
// <keys dir> holds the recorder's own keys, so the strongest forgeries are re-signed with both of them.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { canon, body } from "../plugins/hive-recorder/scripts/core.mjs";
import { verifyFile } from "../plugins/hive-recorder/scripts/verify.mjs";
import { ml_dsa65 } from "../plugins/hive-recorder/scripts/vendor/ml-dsa-65.mjs";

const [src, keys, policy, out, wkey] = process.argv.slice(2);
const base = fs.readFileSync(src, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const wit = fs.readFileSync(src.replace(/\.jsonl$/, ".witness.jsonl"), "utf8");
const sk = crypto.createPrivateKey(fs.readFileSync(path.join(keys, "recorder-ed25519.pem")));
const pq = ml_dsa65.keygen(Uint8Array.from(Buffer.from(fs.readFileSync(path.join(keys, "recorder-ml-dsa-65.seed"), "utf8").trim(), "hex")));
const other = crypto.generateKeyPairSync("ed25519").privateKey;
const otherPub = crypto.createPublicKey(other).export({ format: "jwk" }).x;
const pin = base[0].public_key;
const H = s => crypto.createHash("sha256").update(s).digest("hex");
const clean = { tool: false, paths: [], hosts: [] };

function rebuild(lines, key = sk, withPq = true) {
  let prev = "0".repeat(64);
  return lines.map((l0, i) => {
    const l = { ...body(l0), seq: i, prev };
    if (l.event === "Seal") { l.count = i; l.head = prev; }
    const c = canon(l), h = H(c); prev = h;
    const r = { ...l, hash: h, sig: crypto.sign(null, Buffer.from(c), key).toString("base64url") };
    if (withPq) r.sig_pq = Buffer.from(ml_dsa65.sign(Buffer.from(c), pq.secretKey)).toString("base64url");
    return r;
  });
}
const iEsc = base.findIndex(l => l.event === "PreToolUse" && l.scope && l.scope.outside.hosts.length);
const escId = base[iEsc].tool.use_id;
const iEscOut = base.findIndex(l => l.event !== "PreToolUse" && l.tool && l.tool.use_id === escId);
const iAdm = 1;
const hide = l => l.seq === iEsc ? { ...l, scope: { ...l.scope, outside: clean } } : l;
const widen = l => l.event === "Admission" ? { ...l, scope: { ...l.scope, hosts: [...l.scope.hosts, "huggingface.co"].sort() } } : l;

const cases = [
  ["escape-deleted", "The call to huggingface.co and its result are deleted", "CHAIN_ORDER", () => base.filter((_, i) => i !== iEsc && i !== iEscOut)],
  ["escape-host-rewritten", "The call is edited to say it went to the npm registry", "ENTRY_HASH", () => base.map((l, i) => i === iEsc ? { ...l, scope: { touched: { paths: [], hosts: ["registry.npmjs.org"] }, outside: clean } } : l)],
  ["admission-widened", "huggingface.co is added to the admission after the fact", "ENTRY_HASH", () => base.map(widen)],
  ["admission-removed", "The admission is deleted, so nothing looks out of scope", "CHAIN_ORDER", () => base.filter((_, i) => i !== iAdm)],
  ["failure-turned-success", "The failed call is relabelled as one that worked", "ENTRY_HASH", () => base.map((l, i) => i === iEscOut ? { ...l, event: "PostToolUse" } : l)],
  ["pq-signature-removed", "The ML-DSA-65 signature is stripped from the escape line", "PQ_SIGNATURE", () => base.map((l, i) => i === iEsc ? (({ sig_pq, ...r }) => r)(l) : l)],
  ["pq-signature-swapped", "The escape line gets another line's ML-DSA-65 signature", "PQ_SIGNATURE", () => base.map((l, i) => i === iEsc ? { ...l, sig_pq: base[iEsc - 1].sig_pq } : l)],
  ["scope-hidden-resigned", "The scope check is cleared and the record re-signed with both of the recorder's own keys", "ADMISSION", () => rebuild(base.map(hide))],
  ["admission-moved-resigned", "The admission is moved after the session start and everything re-signed with the recorder's keys", "ADMISSION", () => { const b = base.slice(); [b[1], b[2]] = [b[2], b[1]]; return rebuild(b); }],
  ["escape-deleted-resigned", "The escape is deleted and the whole record re-signed with both of the recorder's own keys", "WITNESS", () => rebuild(base.filter((_, i) => i !== iEsc && i !== iEscOut))],
  ["admission-widened-resigned", "The admission is widened, the scope check cleared, and everything re-signed with the recorder's keys", "ADMISSION", () => rebuild(base.map(widen).map(hide))],
  ["rebuilt-other-key", "The whole record is rebuilt and signed with a different key", "KEY_PIN", () => rebuild(base.map((l, i) => i === 0 ? (({ pq_alg, pq_public_key, ...r }) => ({ ...r, public_key: otherPub }))(l) : l), other, false)],
];
fs.mkdirSync(out, { recursive: true });
const manifest = []; let n = 0;
for (const [id, what, expected, make] of cases) {
  const f = path.join(out, id + ".jsonl");
  fs.writeFileSync(f, make().map(l => JSON.stringify(l)).join("\n") + "\n");
  fs.writeFileSync(f.replace(/\.jsonl$/, ".witness.jsonl"), wit);
  // Checked the way a reviewer would: recorder key, witness key and the policy they were given.
  const r = verifyFile(f, { key: pin, witnessKey: wkey, admission: policy });
  const got = r.first_failure && r.first_failure.gate, ok = !r.ok && got === expected;
  if (ok) n++;
  manifest.push({ id, file: id + ".jsonl", what, expected, got, why: r.first_failure && r.first_failure.why });
  console.log((ok ? "ok   " : "FAIL ") + id + "  " + (got || "accepted") + (r.first_failure ? ", " + r.first_failure.why : ""));
}
fs.writeFileSync(path.join(out, "MANIFEST.json"), JSON.stringify(manifest, null, 2));
console.log(`\n${n} of ${cases.length} rejected at the expected gate.`);
process.exitCode = n === cases.length ? 0 : 1;
