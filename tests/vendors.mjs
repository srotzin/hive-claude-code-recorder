// Four surfaces built on split lines: one vendor's view of a record, a record shared across two
// vendors, a licence statement checked against the witness's memory, and the trail from an answer
// back to the pulls it drew on. Runs the real hook and a real witness with Postgres memory.
//   HIVE_TEST_PG=postgres://... node tests/vendors.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { canon, body, discloseFor, verifyRecord, checkAnswer, statementBody, checkStatement, stubOf } from "../plugins/hive-recorder/scripts/core.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REC = path.join(ROOT, "plugins/hive-recorder/scripts/record.mjs");
const results = [];
const check = (name, ok, detail = "") => { results.push(!!ok); console.log((ok ? "ok   " : "FAIL ") + name + (detail ? "  " + detail : "")); };
if (!process.env.HIVE_TEST_PG) { console.log("set HIVE_TEST_PG"); process.exit(1); }
const seed = crypto.randomBytes(32).toString("hex");
const ws = spawn(process.execPath, [path.join(ROOT, "witness/server.mjs")], { env: { ...process.env, PORT: "18795", WITNESS_ED25519_SEED: seed, DATABASE_URL: process.env.HIVE_TEST_PG, DATABASE_SSL: "off" }, stdio: ["ignore", "pipe", "pipe"] });
await new Promise(r => ws.stdout.on("data", d => String(d).includes("hive-witness on") && r()));
const W = "http://127.0.0.1:18795";
const wkey = (await (await fetch(W + "/v1/witness/key")).json()).witness_key;

const D = fs.mkdtempSync(path.join(os.tmpdir(), "hive-vend-")), P = fs.mkdtempSync(path.join(os.tmpdir(), "hive-vend-p-"));
fs.mkdirSync(path.join(P, ".claude"));
const pol = { purpose: "Risk check", tools: ["ToolSearch", "mcp__market-data__*", "mcp__ref-data__*"], paths: ["**"], hosts: [],
  entitlements: { "market-data": ["futures.brent.*", "futures.wti.eod"], "ref-data": ["issuers.reference"] } };
fs.writeFileSync(path.join(P, ".claude/hive-admission.json"), JSON.stringify(pol));
const env = { ...process.env, HIVE_RECORDER_DIR: D, HIVE_WITNESS_URL: W + "/v1/witness", HIVE_TSA_URL: "off", HIVE_WITNESS_WAIT_MS: "3000" };
const t0 = new Date(Date.now() - 1000).toISOString();
function run(S, evs) { for (const ev of evs) spawnSync(process.execPath, [REC], { input: JSON.stringify({ ...ev, session_id: S, cwd: P }), env }); }
const md = (id, ds, resp) => [
  { hook_event_name: "PreToolUse", tool_name: "mcp__market-data__get_eod", tool_use_id: id, tool_input: { dataset: ds, date: "2026-10-09" } },
  { hook_event_name: "PostToolUse", tool_name: "mcp__market-data__get_eod", tool_use_id: id, tool_input: { dataset: ds, date: "2026-10-09" }, tool_response: resp }];
const S1 = "v1-" + crypto.randomUUID(), S2 = "v2-" + crypto.randomUUID();
const ANSWER = "Brent settled at $84.12. Loan L1000 has a balance of $250,000. Issuer ACME-7731 is rated A-.";
run(S1, [
  { hook_event_name: "SessionStart", source: "startup" },
  { hook_event_name: "UserPromptSubmit", prompt: "check" },
  ...md("a1", "futures.brent.eod", { content: [{ type: "text", text: JSON.stringify({ settle: 84.12 }) }] }),
  { hook_event_name: "PreToolUse", tool_name: "mcp__market-data__get_records", tool_use_id: "a2", tool_input: { dataset: "mortgage.loan-level", limit: 5 } },
  { hook_event_name: "PostToolUse", tool_name: "mcp__market-data__get_records", tool_use_id: "a2", tool_input: { dataset: "mortgage.loan-level", limit: 5 }, tool_response: { rows: [{ loan: "L1000", balance: 250000 }] } },
  { hook_event_name: "PreToolUse", tool_name: "mcp__ref-data__get_issuer", tool_use_id: "b1", tool_input: { dataset: "issuers.reference", id: "ACME-7731" } },
  { hook_event_name: "PostToolUse", tool_name: "mcp__ref-data__get_issuer", tool_use_id: "b1", tool_input: { dataset: "issuers.reference", id: "ACME-7731" }, tool_response: { issuer: "ACME-7731", rating: "A-", shares: 41250000 } },
  { hook_event_name: "Stop", last_assistant_message: ANSWER },
  { hook_event_name: "SessionEnd", reason: "other" },
]);
run(S2, [{ hook_event_name: "SessionStart", source: "startup" }, ...md("c1", "futures.wti.eod", { settle: 79.4 }), { hook_event_name: "Stop", last_assistant_message: "WTI 79.4" }, { hook_event_name: "SessionEnd", reason: "other" }]);
await new Promise(r => setTimeout(r, 800));
const read = S => fs.readFileSync(path.join(D, "records", S + ".jsonl"), "utf8").split("\n").filter(Boolean).map(JSON.parse);
const L1 = read(S1), L2 = read(S2), pub = L1[0].public_key;
const mem = async L => (await (await fetch(W + "/v1/witness/statements?" + new URLSearchParams({ recorder_key: pub, session_fp: c.sha256hex(L[0].session) }))).json()).statements;
const M1 = await mem(L1), M2 = await mem(L2);
const o = (L, m, x = {}) => verifyRecord(L, c, { pin: pub, witnessPin: wkey, memory: { statements: m }, requireMemory: true, ...x });

// Format
const full = o(L1, M1);
check("split record: the full record passes every gate, with witness memory", full.ok, Object.entries(full.gates).map(([k, v]) => k + " " + v).join(" "));
check("split record: entitlements are one line per vendor, right after the admission", L1[2].event === "Entitlement" && L1[2].vendor === "market-data" && L1[3].vendor === "ref-data");
check("split record: the mortgage pull is flagged against the market-data entitlement only", full.summary.outside_admission.length === 1 && full.summary.outside_admission[0].outside.datasets[0] === "mortgage.loan-level");
const raw = fs.readFileSync(path.join(D, "records", S1 + ".jsonl"), "utf8");
check("split record: no figure from any result is in the record", !raw.includes("84.12") && !raw.includes("250000") && !raw.includes("41250000"));

// 1. One vendor's view
const A = discloseFor(L1, "market-data", c.sha256hex), B = discloseFor(L1, "ref-data", c.sha256hex);
const rA = o(A, M1, { allowRedacted: true, discloseFor: "market-data" });
check("disclosure: market-data's copy passes against the witness, other lines hidden", rA.ok && rA.redacted > 0, rA.redacted + " lines hidden, " + JSON.stringify(rA.summary.redacted));
check("disclosure: market-data's copy shows nothing of ref-data's pull", !JSON.stringify(A).includes("issuers.reference") && !JSON.stringify(A).includes("get_issuer"));
check("disclosure: a hidden copy is refused by a plain check", !o(A, M1).ok && o(A, M1).first_failure.gate === "DISCLOSURE");
const iA2 = L1.findIndex(l => l.tool && l.tool.use_id === "a2" && l.event === "PreToolUse");
const T = {
  "pull-hidden": [A.map((l, i) => i === iA2 ? stubOf(L1[i], c.sha256hex) : l), "DISCLOSURE"],
  "stub-relabelled": [A.map((l, i) => i === iA2 ? { ...stubOf(L1[i], c.sha256hex), vendor: "ref-data" } : l), "ENTRY_HASH"],
  "stub-dropped": [A.filter(l => !(l.redacted && l.vendor === "ref-data" && l.event === "PreToolUse")), "CHAIN_ORDER"],
  "line-edited": [A.map((l, i) => i === iA2 ? { ...l, scope: { ...l.scope, touched: { ...l.scope.touched, datasets: ["futures.wti.eod"] } } } : l), "ENTRY_HASH"],
};
for (const [k, [L, g]] of Object.entries(T)) { const r = o(L, M1, { allowRedacted: true, discloseFor: "market-data" }); check("disclosure tamper " + k + ": rejected at " + g, !r.ok && r.first_failure.gate === g, r.first_failure && r.first_failure.why); }

// 2. Two vendors
const rB = o(B, M1, { allowRedacted: true, discloseFor: "ref-data" });
check("two vendors: ref-data's copy of the same session also passes against the same witness memory", rB.ok);
check("two vendors: ref-data's copy hides both market-data pulls", B.filter(l => l.redacted && l.vendor === "market-data" && l.event === "PreToolUse").length === 2);
const rBA = o(B, M1, { allowRedacted: true, discloseFor: "market-data" });
check("two vendors: ref-data's copy handed to market-data is rejected", !rBA.ok && rBA.first_failure.gate === "DISCLOSURE", rBA.first_failure && rBA.first_failure.why);

// 3. Answer trail
const tr = checkAnswer(L1, ANSWER, c);
check("answer trail: the answer is the one recorded, and its figures trace to both vendors' pulls", tr.ok && tr.drew_on.map(d => d.vendor).sort().join() === "market-data,market-data,ref-data", JSON.stringify(tr.drew_on));
check("answer trail: market-data can check the trail from its own copy", checkAnswer(A, ANSWER, c).ok);
const bad = checkAnswer(L1, ANSWER.replace("84.12", "81.12"), c);
check("answer trail: one figure changed in the answer is rejected", !bad.ok, bad.why);

// 4. Statement
const period = { from: t0, to: new Date(Date.now() + 60000).toISOString() };
const sk = crypto.createPrivateKey(fs.readFileSync(path.join(D, "keys/recorder-ed25519.pem")));
const sign = b => crypto.sign(null, Buffer.from(canon(b)), sk).toString("base64url");
const mk = discs => { const b = { ...statementBody(discs, "market-data", period, c), issued_at: new Date().toISOString() }; return { ...b, sig: sign(b) }; };
const dA1 = discloseFor(L1, "market-data", c.sha256hex), dA2 = discloseFor(L2, "market-data", c.sha256hex);
const st = mk([dA1, dA2]);
const sess = (await (await fetch(W + "/v1/witness/sessions?" + new URLSearchParams({ recorder_key: pub, from: period.from, to: period.to }))).json()).sessions;
const memo = { [c.sha256hex(L1[0].session)]: M1, [c.sha256hex(L2[0].session)]: M2 };
const vk = crypto.generateKeyPairSync("ed25519"), vpub = vk.publicKey.export({ format: "jwk" }).x;
const accept = s => { const { accepted, ...x } = s; const a = { accepted_at: new Date().toISOString() }; return { ...x, accepted: { vendor_key: vpub, ...a, sig: crypto.sign(null, Buffer.from(canon({ statement_sha256: c.sha256hex(canon(x)), ...a })), vk.privateKey).toString("base64url") } }; };
const stA = accept(st);
const opt = { recorderPin: pub, witnessPin: wkey, memory: memo, witnessSessions: sess, vendorPin: vpub };
const g = checkStatement(stA, [dA1, dA2], c, opt);
check("statement: two sessions, usage and the outside pull match the records and the witness, accepted by the vendor", g.ok && g.sessions === 2 && g.outside === 1, JSON.stringify(g));
const lower = (() => { const { sig, accepted, ...b } = st; const b2 = { ...b, usage: b.usage.map(u => ({ ...u, outside: 0 })), outside: [] }; return { ...b2, sig: sign(b2) }; })();
const ST = {
  "outside-dropped": [lower, [dA1, dA2], "USAGE"],
  "session-left-out": [mk([dA2]), [dA2], "COMPLETE"],
  "acceptance-moved": [{ ...lower, accepted: stA.accepted }, [dA1, dA2], "USAGE"],
};
for (const [k, [s, d, gate]] of Object.entries(ST)) { const r = checkStatement(s, d, c, opt); check("statement tamper " + k + ": rejected at " + gate, !r.ok && r.step === gate, r.why); }
const acc2 = (() => { const s = accept(st); return { ...s, accepted: { ...s.accepted, accepted_at: "2026-01-01T00:00:00.000Z" } }; })();
const ra = checkStatement(acc2, [dA1, dA2], c, opt);
check("statement tamper acceptance-redated: rejected at ACCEPTED", !ra.ok && ra.step === "ACCEPTED", ra.why);

ws.kill();
const n = results.filter(Boolean).length;
console.log(`\n${n} of ${results.length} checks passed.`);
process.exitCode = n === results.length ? 0 : 1;
