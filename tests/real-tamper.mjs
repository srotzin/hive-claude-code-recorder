// Build tamper cases from a real recorded session.
//   node tests/real-tamper.mjs <session.jsonl> <recorder.pem> <out dir> <witness key>
// The witness statements are copied unchanged next to every case.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { canon, body } from "../plugins/hive-recorder/scripts/core.mjs";
import { verifyFile } from "../plugins/hive-recorder/scripts/verify.mjs";

const [src, pem, out, wkey] = process.argv.slice(2);
const base = fs.readFileSync(src, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const wit = fs.readFileSync(src.replace(/\.jsonl$/, ".witness.jsonl"), "utf8");
const sk = crypto.createPrivateKey(fs.readFileSync(pem));
const other = crypto.generateKeyPairSync("ed25519").privateKey;
const otherPub = crypto.createPublicKey(other).export({ format: "jwk" }).x;
const pin = base[0].public_key;
const H = s => crypto.createHash("sha256").update(s).digest("hex");

// Rebuild a whole record consistently with a key, fixing seals. This is the strongest forgery.
function rebuild(lines, key) {
  let prev = "0".repeat(64);
  return lines.map((l0, i) => { const l = { ...body(l0), seq: i, prev }; if (l.event === "Seal") { l.count = i; l.head = prev; } const c = canon(l); const h = H(c); prev = h; return { ...l, hash: h, sig: crypto.sign(null, Buffer.from(c), key).toString("base64url") }; });
}
const ids = base.map(l => l.tool && l.tool.use_id);
const pre = base.filter(l => l.event === "PreToolUse");
const denied = pre.find(p => !base.some(l => l.tool && l.tool.use_id === p.tool.use_id && l.event !== "PreToolUse"));
const iDenied = denied.seq;
const iEditPost = base.findIndex(l => l.event === "PostToolUse" && l.tool.name === "Edit");
const iFirstTest = base.findIndex(l => l.event === "PostToolUse" && l.tool.name === "Bash");
const iSecondTest = base.findIndex((l, i) => i > iFirstTest && l.event === "PostToolUse" && l.tool.name === "Bash");
const lastWitnessed = Math.max(...wit.trim().split("\n").map(l => JSON.parse(l).count));

const fakeOutcome = { ...body(denied), event: "PostToolUse", fp: { ...denied.fp, response: "0".repeat(64) }, bytes: { ...denied.bytes, response: 107 }, duration_ms: 80 };
const cases = [
  ["denied-call-deleted", "The curl call Claude Code denied is deleted, so it looks like it was never asked for", "CHAIN_ORDER", () => base.filter((_, i) => i !== iDenied)],
  ["denied-call-relabelled", "The denied curl call is relabelled as a harmless Read", "ENTRY_HASH", () => base.map((l, i) => i === iDenied ? { ...l, tool: { ...l.tool, name: "Read" } } : l)],
  ["failing-test-hidden", "The first test run's output fingerprint is swapped for the passing run's", "ENTRY_HASH", () => base.map((l, i) => i === iFirstTest ? { ...l, fp: { ...l.fp, response: base[iSecondTest].fp.response } } : l)],
  ["edit-time-moved", "The code edit's time is moved a day earlier", "ENTRY_HASH", () => base.map((l, i) => i === iEditPost ? { ...l, t: new Date(Date.parse(l.t) - 86400000).toISOString() } : l)],
  ["edit-and-test-swapped", "The edit and the first test run swap places", "CHAIN_ORDER", () => { const b = base.slice(); [b[iFirstTest], b[iEditPost]] = [b[iEditPost], b[iFirstTest]]; return b; }],
  ["prompt-fingerprint-changed", "The user's prompt fingerprint is replaced", "ENTRY_HASH", () => base.map(l => l.event === "UserPromptSubmit" ? { ...l, fp: { ...l.fp, prompt: "f".repeat(64) } } : l)],
  ["signature-forged", "One line is re-signed with another key but keeps the original key id", "SIGNATURE", () => base.map((l, i) => { if (i !== iEditPost) return l; const b = body(l); const c = canon(b); return { ...b, hash: H(c), sig: crypto.sign(null, Buffer.from(c), other).toString("base64url") }; })],
  ["seal-shortened", "A seal is edited to cover one line fewer", "ENTRY_HASH", () => base.map(l => l.event === "Seal" ? { ...l, count: l.count - 1 } : l)],
  ["rebuilt-denied-call-removed", "The whole record is rebuilt and re-signed with the recorder's own key, denied call removed", "WITNESS", () => rebuild(base.filter((_, i) => i !== iDenied), sk)],
  ["rebuilt-denied-call-ran", "Rebuilt with the recorder's own key, adding a fake outcome so the denied call looks like it ran", "WITNESS", () => rebuild([...base.slice(0, iDenied + 1), fakeOutcome, ...base.slice(iDenied + 1)], sk)],
  ["session-end-trimmed", "The session end and last seal are cut off", "WITNESS", () => base.slice(0, lastWitnessed - 1)],
  ["rebuilt-other-key", "The whole record is rebuilt and signed with a different key", "KEY_PIN", () => rebuild(base.map((l, i) => i === 0 ? { ...l, public_key: otherPub } : l), other)],
];

fs.mkdirSync(out, { recursive: true });
for (const f of fs.readdirSync(out)) fs.unlinkSync(path.join(out, f));
const manifest = []; let ok = 0;
for (const [id, what, expect, make] of cases) {
  const f = path.join(out, id + ".jsonl");
  fs.writeFileSync(f, make().map(l => JSON.stringify(l)).join("\n") + "\n");
  fs.writeFileSync(f.replace(/\.jsonl$/, ".witness.jsonl"), wit);
  const r = verifyFile(f, { key: pin, witnessKey: wkey });
  const pass = !r.ok && r.first_failure && r.first_failure.gate === expect;
  if (pass) ok++;
  manifest.push({ id, what, file: id + ".jsonl", expected: expect, got: r.first_failure && r.first_failure.gate, why: r.first_failure && r.first_failure.why });
  console.log((pass ? "rejected " : "UNEXPECTED ") + id + "  " + (r.first_failure ? r.first_failure.gate + ", " + r.first_failure.why : "accepted"));
}
fs.writeFileSync(path.join(out, "MANIFEST.json"), JSON.stringify(manifest, null, 2));
console.log(`${ok} of ${cases.length} rejected at the expected gate`);
process.exitCode = ok === cases.length ? 0 : 1;
