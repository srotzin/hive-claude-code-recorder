// Delivery match: the vendor's own signed, witnessed delivery log against the firm's record.
// Runs the real hook, the real vendor delivery log and a real witness with Postgres memory.
//   HIVE_TEST_PG=postgres://... node tests/deliveries.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canon, discloseFor, checkDeliveries, matchBody, checkMatch, checkDerived, checkAnswer } from "../plugins/hive-recorder/scripts/core.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";
import { openDeliveryLog } from "../vendor-kit/delivery-log.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REC = path.join(ROOT, "plugins/hive-recorder/scripts/record.mjs");
const results = [];
const check = (name, ok, detail = "") => { results.push(!!ok); console.log((ok ? "ok   " : "FAIL ") + name + (detail ? "  " + detail : "")); };
if (!process.env.HIVE_TEST_PG) { console.log("set HIVE_TEST_PG"); process.exit(1); }
const ws = spawn(process.execPath, [path.join(ROOT, "witness/server.mjs")], { env: { ...process.env, PORT: "18796", WITNESS_ED25519_SEED: crypto.randomBytes(32).toString("hex"), DATABASE_URL: process.env.HIVE_TEST_PG, DATABASE_SSL: "off" }, stdio: ["ignore", "pipe", "pipe"] });
await new Promise(r => ws.stdout.on("data", d => String(d).includes("hive-witness on") && r()));
const W = "http://127.0.0.1:18796";
const wkey = (await (await fetch(W + "/v1/witness/key")).json()).witness_key;

const D = fs.mkdtempSync(path.join(os.tmpdir(), "hive-dl-")), P = fs.mkdtempSync(path.join(os.tmpdir(), "hive-dl-p-")), V = fs.mkdtempSync(path.join(os.tmpdir(), "hive-dl-v-"));
fs.mkdirSync(path.join(P, ".claude"));
fs.writeFileSync(path.join(P, ".claude/hive-admission.json"), JSON.stringify({ purpose: "Risk check", tools: ["mcp__market-data__*"], paths: ["**"], hosts: [], entitlements: { "market-data": ["futures.brent.*", "futures.wti.eod"] } }));
const vk = crypto.generateKeyPairSync("ed25519").privateKey, vkPem = path.join(V, "vendor.pem");
fs.writeFileSync(vkPem, vk.export({ type: "pkcs8", format: "pem" }));
const customer = "firm-" + crypto.randomUUID().slice(0, 8);
const vlogFile = path.join(V, "deliveries.jsonl");
const vlog = openDeliveryLog({ file: vlogFile, keyPem: vkPem, vendor: "market-data", customer, log: "market-data/" + customer, witnesses: [W + "/v1/witness"] });
const env = { ...process.env, HIVE_RECORDER_DIR: D, HIVE_WITNESS_URL: W + "/v1/witness", HIVE_TSA_URL: "off", HIVE_WITNESS_WAIT_MS: "3000" };
const t0 = new Date(Date.now() - 1000).toISOString();
const run = (S, evs) => { for (const ev of evs) spawnSync(process.execPath, [REC], { input: JSON.stringify({ ...ev, session_id: S, cwd: P }), env }); };
async function pull(S, id, tool, ds, body) {
  const delivery = await vlog.deliver({ tool, datasets: [ds], body });
  const name = "mcp__market-data__" + tool, input = { dataset: ds };
  run(S, [{ hook_event_name: "PreToolUse", tool_name: name, tool_use_id: id, tool_input: input },
    { hook_event_name: "PostToolUse", tool_name: name, tool_use_id: id, tool_input: input, tool_response: [{ type: "text", text: JSON.stringify({ ...body, delivery }) }] }]);
}
const S1 = "d1-" + crypto.randomUUID();
const rows = { dataset: "futures.brent.eod", rows: [{ day: "2026-10-07", settle: 83.6 }, { day: "2026-10-08", settle: 84.2 }, { day: "2026-10-09", settle: 84.8 }] };
const ANSWER = "Brent settled at 83.6, 84.2 and 84.8 over three days, an average of 84.2 and a total of 252.6.";
run(S1, [{ hook_event_name: "SessionStart", source: "startup" }, { hook_event_name: "UserPromptSubmit", prompt: "check" }]);
await pull(S1, "a1", "get_records", "futures.brent.eod", rows);
await pull(S1, "a2", "get_eod", "futures.wti.eod", { dataset: "futures.wti.eod", settle: 79.4 });
run(S1, [{ hook_event_name: "Stop", last_assistant_message: ANSWER }, { hook_event_name: "SessionEnd", reason: "other" }]);
// A pull straight from the vendor, outside the agent and its recorder.
await vlog.deliver({ tool: "get_records", datasets: ["mortgage.loan-level"], body: { dataset: "mortgage.loan-level", rows: [{ loan: "L1000", balance: 250000 }] } });
await new Promise(r => setTimeout(r, 800));
const t1 = new Date(Date.now() + 1000).toISOString(), period = { from: t0, to: t1 };

const readL = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
const L1 = readL(path.join(D, "records", S1 + ".jsonl")), pub = L1[0].public_key;
const A1 = discloseFor(L1, "market-data", c.sha256hex);
const VL = readL(vlogFile), VP = readL(vlogFile.replace(/\.jsonl$/, ".private.jsonl"));
const get = async (q) => (await (await fetch(W + "/v1/witness/" + q)).json());
const recMem = { [c.sha256hex(S1)]: (await get("statements?" + new URLSearchParams({ recorder_key: pub, session_fp: c.sha256hex(S1) }))).statements };
const logMem = (await get("statements?" + new URLSearchParams({ recorder_key: vlog.pub, session_fp: vlog.logFp }))).statements;
const sessions = (await get("sessions?" + new URLSearchParams({ recorder_key: pub, from: t0, to: t1 }))).sessions;

check("the firm's result lines carry a delivery fingerprint", L1.filter(l => l.event === "PostToolUse").every(l => /^[0-9a-f]{64}$/.test(l.delivery_fp || "")));
check("the delivery id adds no figures to the result", !L1.some(l => l.event === "PostToolUse" && l.vals && l.vals.length > 6));
const dv = checkDeliveries(VL, c, { vendorPin: vlog.pub, witnessPin: wkey, memory: logMem, requireMemory: true });
check("the vendor's delivery log checks against the witness", dv.ok && dv.deliveries === 3 && dv.witnessed === 3, JSON.stringify(dv));
const mb = matchBody([A1], VL, "market-data", period, c);
check("match: two pulls matched, one delivery with no record", mb.matches.length === 2 && mb.unrecorded.length === 1 && mb.unrecorded[0].datasets[0] === "mortgage.loan-level" && mb.unmatched.length === 0, JSON.stringify({ m: mb.matches.length, u: mb.unrecorded, x: mb.unmatched }));
const b = { ...mb, issued_at: new Date().toISOString(), vendor_key: vlog.pub };
const M = { ...b, sig: crypto.sign(null, Buffer.from(canon(b)), vk).toString("base64url") };
const rk = crypto.createPrivateKey(fs.readFileSync(path.join(D, "keys", "recorder-ed25519.pem")));
const acc = { accepted_at: new Date().toISOString() };
const MA = { ...M, accepted: { recorder_key: pub, ...acc, sig: crypto.sign(null, Buffer.from(canon({ match_sha256: c.sha256hex(canon(M)), ...acc })), rk).toString("base64url") } };
const opts = { recorderPin: pub, vendorPin: vlog.pub, witnessPin: wkey, memory: recMem, logMemory: logMem, witnessSessions: sessions };
const g = checkMatch(MA, [A1], VL, c, opts);
check("match: signed by the vendor, accepted by the firm, checks against both logs and the witness", g.ok && g.matched === 2 && g.unrecorded === 1 && g.accepted_at, JSON.stringify(g));
const dd = checkDerived(A1, ANSWER, VL, VP, "market-data", c);
check("derived: the average and the total are traced to delivery 0", dd.ok && dd.derived.some(x => x.op === "average" && x.figure === "84.2") && dd.derived.some(x => x.op === "sum" && x.figure === "252.6"), JSON.stringify(dd.derived));
check("derived: the three settles repeat delivery 0 directly", dd.ok && ["83.6", "84.8"].every(f => dd.direct.some(x => x.figure === f && x.delivery_seq === 0)));

// Tamper cases
const reSign = L => { let prev = "0".repeat(64); return L.map((l, i) => { const { hash, sig, ...x } = l; const y = { ...x, seq: i, prev }; const h = c.sha256hex(canon(y)); prev = h; return { ...y, hash: h, sig: crypto.sign(null, Buffer.from(canon(y)), vk).toString("base64url") }; }); };
const expect = (name, r, step) => check("tamper: " + name, !r.ok && r.step === step, (r.step || "passed") + ": " + (r.why || ""));
expect("the vendor erases the outside pull and re-signs", checkMatch(MA, [A1], reSign(VL.slice(0, 2)), c, opts), "DELIVERIES");
const extra = { ...VL[2], seq: 3, t: new Date().toISOString(), delivery_fp: c.sha256hex("dl-fake"), datasets: ["futures.brent.eod"] };
expect("the vendor adds a delivery that never happened and re-signs", checkDeliveries(reSign([...VL, extra]), c, { vendorPin: vlog.pub, witnessPin: wkey, memory: logMem, requireMemory: true }), "WITNESS");
expect("the vendor relabels a delivery's dataset and re-signs", checkMatch(MA, [A1], reSign(VL.map((l, i) => i === 1 ? { ...l, datasets: ["futures.brent.eod"] } : l)), c, opts), "DELIVERIES");
const { sig: _s, accepted: _a, ...mb2 } = MA;
const hidden = { ...mb2, unrecorded: [] };
expect("the match hides the outside pull", checkMatch({ ...hidden, sig: crypto.sign(null, Buffer.from(canon(hidden)), vk).toString("base64url") }, [A1], VL, c, { ...opts }), "MATCH");
expect("the firm hands over a copy with a delivery fingerprint changed", checkMatch(MA, [A1.map(l => l.seq === 5 && !l.redacted ? { ...l, delivery_fp: c.sha256hex("dl-other") } : l)], VL, c, opts), "RECORD");
const left = { ...mb2, sessions: [] };
expect("the match leaves out a session the witness saw", checkMatch({ ...left, sig: crypto.sign(null, Buffer.from(canon(left)), vk).toString("base64url") }, [], VL, c, opts), "COMPLETE");
expect("the firm's acceptance is moved to another match", checkMatch({ ...M, issued_at: "2026-01-01T00:00:00.000Z", sig: crypto.sign(null, Buffer.from(canon({ ...b, issued_at: "2026-01-01T00:00:00.000Z" })), vk).toString("base64url"), accepted: MA.accepted }, [A1], VL, c, opts), "ACCEPTED");
expect("the vendor swaps the delivered rows to claim a derivation", checkDerived(A1, ANSWER, VL, VP.map(p => p.seq === 0 ? { ...p, body: { ...p.body, rows: [{ settle: 84 }, { settle: 84 }] } } : p), "market-data", c), "BODY");
expect("the firm changes a figure in the answer", checkDerived(A1, ANSWER.replace("252.6", "260.6"), VL, VP, "market-data", c), "ANSWER");

ws.kill();
const n = results.filter(Boolean).length;
console.log(`\n${n} of ${results.length} checks passed.`);
fs.writeFileSync(path.join(ROOT, "tests", "RESULTS-deliveries.txt"), `${n} of ${results.length} checks passed.\n`);
process.exitCode = n === results.length ? 0 : 1;
