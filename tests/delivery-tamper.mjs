// Builds and checks the tamper cases for examples/claude-code-deliveries against the live witness.
//   node tests/delivery-tamper.mjs <vendor-key.pem>      (the stand-in vendor key; not in the repository)
// Writes tamper/*.json[l], tamper/MANIFEST.json and copies/witness-*.json (a saved copy of the witness's memory).
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { canon, checkMatch, checkDerived, checkDeliveries } from "../plugins/hive-recorder/scripts/core.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const E = path.join(ROOT, "examples/claude-code-deliveries"), T = path.join(E, "tamper");
const W = process.env.HIVE_WITNESS || "https://witness.thehiveryiq.com", WKEY = "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE";
const vk = crypto.createPrivateKey(fs.readFileSync(process.argv[2]));
const rl = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse), wl = (f, L) => fs.writeFileSync(f, L.map(l => JSON.stringify(l)).join("\n") + "\n");
const A1 = rl(path.join(E, "copies/session-1.market-data.jsonl")), A2 = rl(path.join(E, "copies/session-2.market-data.jsonl"));
const VL = rl(path.join(E, "vendor/market-data.deliveries.jsonl")), VP = rl(path.join(E, "vendor/market-data.delivered-bodies.jsonl"));
const M = JSON.parse(fs.readFileSync(path.join(E, "copies/match.market-data.json"), "utf8"));
const ANSWER = fs.readFileSync(path.join(E, "answer-1.txt"), "utf8");
const get = async q => { const r = await fetch(W + "/v1/witness/" + q); if (!r.ok) throw new Error(q + " " + r.status); return r.json(); };
const sfp = L => c.sha256hex(String(L[0].session));
const memory = {};
for (const L of [A1, A2]) memory[sfp(L)] = (await get("statements?" + new URLSearchParams({ recorder_key: M.recorder_key, session_fp: sfp(L) }))).statements;
const logMemory = (await get("statements?" + new URLSearchParams({ recorder_key: M.vendor_key, session_fp: VL[0].log }))).statements;
const witnessSessions = (await get("sessions?" + new URLSearchParams({ recorder_key: M.recorder_key, from: M.period.from, to: M.period.to }))).sessions;
fs.writeFileSync(path.join(E, "copies/witness-memory.json"), JSON.stringify({ sessions: memory, log: logMemory, witness_sessions: witnessSessions }));
const opts = { recorderPin: M.recorder_key, vendorPin: M.vendor_key, witnessPin: WKEY, memory, logMemory, witnessSessions };

let ok = 0, all = 0;
const say = (name, good, d) => { all++; if (good) ok++; console.log((good ? "ok   " : "FAIL ") + name + "  " + d); };
const g = checkMatch(M, [A1, A2], VL, c, opts);
say("genuine: the match holds against both logs and the live witness", g.ok && g.matched === 3 && g.unrecorded === 1 && g.unmatched === 0 && g.accepted_at, JSON.stringify(g));
const dv = checkDeliveries(VL, c, { vendorPin: M.vendor_key, witnessPin: WKEY, memory: logMemory, requireMemory: true });
say("genuine: every delivery in the vendor's log was witnessed", dv.ok && dv.witnessed === VL.length, JSON.stringify(dv));
const dd = checkDerived(A1, ANSWER, VL, VP, "market-data", c);
say("genuine: the answer's total and average are traced to the mortgage delivery", dd.ok && dd.derived.some(x => x.op === "sum") && dd.derived.some(x => x.op === "average"), JSON.stringify(dd.derived));

const reSign = L => { let prev = "0".repeat(64); return L.map((l, i) => { const { hash, sig, ...x } = l; const y = { ...x, seq: i, prev }; const h = c.sha256hex(canon(y)); prev = h; return { ...y, hash: h, sig: crypto.sign(null, Buffer.from(canon(y)), vk).toString("base64url") }; }); };
const { sig: _s, accepted: _a, ...mb } = M;
const signM = b => ({ ...b, sig: crypto.sign(null, Buffer.from(canon(b)), vk).toString("base64url") });
const mortgage = VL.findIndex(d => d.datasets.includes("mortgage.loan-level"));
fs.rmSync(T, { recursive: true, force: true }); fs.mkdirSync(T);
const G = { "match.json": "../copies/match.market-data.json", "s1.jsonl": "../copies/session-1.market-data.jsonl", "s2.jsonl": "../copies/session-2.market-data.jsonl", "vlog.jsonl": "../vendor/market-data.deliveries.jsonl", "bodies.jsonl": "../vendor/market-data.delivered-bodies.jsonl", "answer": "../answer-1.txt" };
const cases = [
  { group: "deliveries", id: "outside-pull-erased", what: "The vendor erases the pull made outside the agent, and re-signs its log", expected: "DELIVERIES", kind: "match", files: { "vlog.jsonl": reSign(VL.filter((_, i) => i !== VL.length - 1)) } },
  { group: "deliveries", id: "delivery-invented", what: "The vendor adds a delivery that never happened, to bill for it, and re-signs", expected: "DELIVERIES", kind: "match",
    files: { "vlog.jsonl": reSign([...VL, { ...VL[0], t: new Date(Date.parse(VL[VL.length - 1].t) + 1000).toISOString(), delivery_fp: c.sha256hex("dl-invented") }]) } },
  { group: "deliveries", id: "dataset-relabelled", what: "The vendor relabels the mortgage delivery as Brent, and re-signs", expected: "DELIVERIES", kind: "match",
    files: { "vlog.jsonl": reSign(VL.map((d, i) => i === mortgage ? { ...d, datasets: ["futures.brent.eod"] } : d)) } },
  { group: "match", id: "outside-pull-hidden", what: "The match leaves out the pull the recorder never saw", expected: "MATCH", kind: "match", files: { "match.json": signM({ ...mb, unrecorded: [] }) } },
  { group: "match", id: "session-left-out", what: "The match leaves out a session the witness saw", expected: "COMPLETE", kind: "match",
    files: { "match.json": signM({ ...mb, sessions: mb.sessions.filter(s => s.session_fp !== sfp(A2)), matches: mb.matches.filter(m => m.session_fp !== sfp(A2)) }), "s2.jsonl": null } },
  { group: "match", id: "copy-fingerprint-changed", what: "The firm's copy points a pull at a different delivery", expected: "RECORD", kind: "match",
    files: { "s1.jsonl": A1.map(l => !l.redacted && l.delivery_fp && l.vendor === "market-data" ? { ...l, delivery_fp: c.sha256hex("dl-other") } : l) } },
  { group: "match", id: "acceptance-moved", what: "The firm's acceptance is moved onto a different match", expected: "ACCEPTED", kind: "match",
    files: { "match.json": { ...signM({ ...mb, issued_at: "2026-10-01T00:00:00.000Z" }), accepted: M.accepted } } },
  { group: "derived", id: "rows-swapped", what: "The vendor swaps the delivered rows to change what the answer was built from", expected: "BODY", kind: "derived",
    files: { "bodies.jsonl": VP.map(p => p.seq === mortgage ? { ...p, body: { ...p.body, rows: p.body.rows.slice(0, 4) } } : p) } },
  { group: "derived", id: "total-changed", what: "The firm hands over the answer with the total changed", expected: "ANSWER", kind: "derived", files: { answer: ANSWER.replace("1,260,000", "1,250,000") } },
];
const man = [];
for (const t of cases) {
  const files = {};
  for (const [k, def] of Object.entries(G)) {
    if (!(k in t.files)) { files[k] = def; continue; }
    const v = t.files[k];
    if (v === null) continue;
    const name = t.id + "." + k;
    if (k.endsWith(".jsonl")) wl(path.join(T, name), v); else if (k === "answer") fs.writeFileSync(path.join(T, name), v); else fs.writeFileSync(path.join(T, name), JSON.stringify(v, null, 1));
    files[k] = name;
  }
  const rd = k => { const f = path.join(T, files[k]); return k.endsWith(".jsonl") ? rl(f) : k === "answer" ? fs.readFileSync(f, "utf8") : JSON.parse(fs.readFileSync(f, "utf8")); };
  let r;
  if (t.kind === "match") r = checkMatch(rd("match.json"), ["s1.jsonl", "s2.jsonl"].filter(k => files[k]).map(rd), rd("vlog.jsonl"), c, opts);
  else r = checkDerived(rd("s1.jsonl"), rd("answer"), rd("vlog.jsonl"), rd("bodies.jsonl"), "market-data", c);
  const got = r.ok ? null : r.step;
  say("tamper: " + t.what, got === t.expected, (got || "passed") + ": " + (r.why || ""));
  man.push({ group: t.group, id: t.id, what: t.what, kind: t.kind, files, expected: t.expected, got, why: r.why || null });
}
fs.writeFileSync(path.join(T, "MANIFEST.json"), JSON.stringify(man, null, 1));
console.log(`\n${ok} of ${all} passed.`);
process.exitCode = ok === all ? 0 : 1;
