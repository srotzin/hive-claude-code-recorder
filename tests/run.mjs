// Test suite for the Hive recorder. Runs the real hook script as Claude Code would:
// one process per event, JSON on stdin, exit code and stdout checked.
//   node tests/run.mjs
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verifyFile } from "../plugins/hive-recorder/scripts/verify.mjs";
import { canon, body, verifyRecord } from "../plugins/hive-recorder/scripts/core.mjs";
import { c as nodeCrypto } from "../plugins/hive-recorder/scripts/verify.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REC = path.join(ROOT, "plugins/hive-recorder/scripts/record.mjs");
const results = [];
const check = (name, ok, detail = "") => { results.push({ name, ok: !!ok, detail }); console.log((ok ? "ok   " : "FAIL ") + name + (detail ? "  " + detail : "")); };
const tmp = p => fs.mkdtempSync(path.join(os.tmpdir(), p));

function hook(ev, dir, extraEnv = {}) {
  const r = spawnSync(process.execPath, [REC], { input: JSON.stringify(ev), env: { ...process.env, HIVE_RECORDER_DIR: dir, HIVE_WITNESS_URL: "off", HIVE_TSA_URL: "off", ...extraEnv }, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function hookAsync(ev, dir) {
  return new Promise(res => { const p = spawn(process.execPath, [REC], { env: { ...process.env, HIVE_RECORDER_DIR: dir, HIVE_WITNESS_URL: "off", HIVE_TSA_URL: "off" } }); let out = ""; p.stdout.on("data", d => out += d); p.on("close", code => res({ code, out })); p.stdin.end(JSON.stringify(ev)); });
}

// The payload shapes below follow Claude Code's hooks reference (code.claude.com/docs/en/hooks).
const S = "sess-" + crypto.randomUUID();
const common = { session_id: S, transcript_path: "/home/dev/.claude/projects/demo/" + S + ".jsonl", cwd: "/home/dev/acme-billing", permission_mode: "default" };
const SECRET = "sk-live-THIS-SHOULD-NEVER-APPEAR";
const events = [
  { ...common, hook_event_name: "SessionStart", source: "startup", model: "claude-opus-5" },
  { ...common, hook_event_name: "UserPromptSubmit", prompt: "Fix the failing invoice test. The key is " + SECRET },
  { ...common, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "npm test", description: "Run test suite" }, tool_use_id: "toolu_01" },
  { ...common, hook_event_name: "PostToolUseFailure", tool_name: "Bash", tool_input: { command: "npm test", description: "Run test suite" }, tool_use_id: "toolu_01", error: "Exit code 1\nError: Cannot find module 'express'", is_interrupt: false, duration_ms: 4187 },
  { ...common, hook_event_name: "PreToolUse", tool_name: "Edit", tool_input: { file_path: "/home/dev/acme-billing/src/invoice.js", old_string: "total * 1.1", new_string: "total * 1.08" }, tool_use_id: "toolu_02" },
  { ...common, hook_event_name: "PostToolUse", tool_name: "Edit", tool_input: { file_path: "/home/dev/acme-billing/src/invoice.js", old_string: "total * 1.1", new_string: "total * 1.08" }, tool_response: { filePath: "/home/dev/acme-billing/src/invoice.js", success: true }, tool_use_id: "toolu_02", duration_ms: 12 },
  { ...common, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "curl -X POST https://api.stripe.com/v1/refunds -d amount=9900", description: "Issue refund" }, tool_use_id: "toolu_03" },
  { ...common, hook_event_name: "PreToolUse", tool_name: "mcp__billing__get_invoice", tool_input: { id: "INV-2207" }, tool_use_id: "toolu_04", mcp_server: { name: "billing", source: "project" } },
  { ...common, hook_event_name: "PostToolUse", tool_name: "mcp__billing__get_invoice", tool_input: { id: "INV-2207" }, tool_response: { total: 9900, currency: "usd" }, tool_use_id: "toolu_04", duration_ms: 230, mcp_server: { name: "billing", source: "project" } },
  { ...common, hook_event_name: "Stop", stop_hook_active: false, last_assistant_message: "I fixed the tax rate in invoice.js. I did not issue the refund." },
  { ...common, hook_event_name: "SessionEnd", reason: "prompt_input_exit" },
];

// 1. Contract run: every event exits 0 and prints nothing.
const D = tmp("hive-rec-");
let allQuiet = true;
for (const ev of events) { const r = hook(ev, D); if (r.code !== 0 || r.out !== "") allQuiet = false; }
check("each documented event exits 0 and prints nothing to stdout", allQuiet);
const file = path.join(D, "records", S + ".jsonl");
const r1 = verifyFile(file);
check("the session record verifies", r1.ok, JSON.stringify(r1.gates));
check("record has key line, 11 events and 2 seals", r1.entries === 14, r1.entries + " lines");
check("record ends sealed", r1.sealed);
const s = r1.summary;
check("summary: 4 asked, 2 completed, 1 failed", s.tool_calls_asked === 4 && s.tool_calls_completed === 2 && s.tool_calls_failed === 1);
check("summary: the refund call was asked with no outcome", s.asked_without_outcome.length === 1 && s.asked_without_outcome[0].tool === "Bash");
check("summary: MCP tool name kept", !!s.tools_completed["mcp__billing__get_invoice"]);

// 2. Privacy: no raw content in anything written.
const written = fs.readdirSync(path.join(D, "records")).map(f => fs.readFileSync(path.join(D, "records", f), "utf8")).join("\n");
const leaks = [SECRET, "npm test", "invoice.js", "total * 1.08", "api.stripe.com", "INV-2207", "I fixed the tax", "acme-billing", "Cannot find module"].filter(x => written.includes(x));
check("no prompt, input, output, path or message text in the record", leaks.length === 0, leaks.join(", "));

// 3. Reveal: the owner can prove one value without exposing the rest.
const vf = path.join(D, "value.json"); fs.writeFileSync(vf, JSON.stringify(events[6].tool_input));
const rv = spawnSync(process.execPath, [path.join(ROOT, "plugins/hive-recorder/scripts/verify.mjs"), "reveal", file, "--seq", "7", "--field", "input", "--value", vf, "--fingerprint-key", path.join(D, "keys/fingerprint.key")], { encoding: "utf8" });
check("reveal: the real refund command matches its fingerprint", rv.status === 0 && rv.stdout.startsWith("MATCH"), rv.stdout.trim());
fs.writeFileSync(vf, JSON.stringify({ ...events[6].tool_input, command: "curl -X POST https://api.stripe.com/v1/refunds -d amount=99" }));
const rv2 = spawnSync(process.execPath, [path.join(ROOT, "plugins/hive-recorder/scripts/verify.mjs"), "reveal", file, "--seq", "7", "--field", "input", "--value", vf, "--fingerprint-key", path.join(D, "keys/fingerprint.key")], { encoding: "utf8" });
check("reveal: a different amount does not match", rv2.status === 1);

// 4. Fail open: an unwritable data directory still exits 0 with no output.
const ro = tmp("hive-ro-"); fs.chmodSync(ro, 0o500);
const rf = hook(events[2], path.join(ro, "nested"));
check("unwritable storage: still exits 0, prints nothing", rf.code === 0 && rf.out === "", "exit " + rf.code);
const rg = spawnSync(process.execPath, [REC], { input: "not json", env: { ...process.env, HIVE_RECORDER_DIR: tmp("hive-bad-"), HIVE_WITNESS_URL: "off", HIVE_TSA_URL: "off" }, encoding: "utf8" });
check("malformed input: still exits 0, prints nothing", rg.status === 0 && rg.stdout === "");

// 5. Parallel hooks: Claude Code runs matching hooks in parallel. 40 at once must chain cleanly.
const P = tmp("hive-par-"), PS = "par-" + crypto.randomUUID();
const t0 = Date.now();
const rs = await Promise.all(Array.from({ length: 40 }, (_, i) => hookAsync({ ...common, session_id: PS, hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/f" + i }, tool_use_id: "toolu_p" + i }, P)));
const pr = verifyFile(path.join(P, "records", PS + ".jsonl"));
check("40 parallel hooks: all exit 0, one valid chain of 41 lines", rs.every(x => x.code === 0) && pr.ok && pr.entries === 41, `${pr.entries} lines in ${Date.now() - t0} ms`);

// 6. Latency: median time for one hook process.
const L = tmp("hive-lat-"), times = [];
for (let i = 0; i < 25; i++) { const a = process.hrtime.bigint(); hook({ ...common, session_id: "lat", hook_event_name: "PostToolUse", tool_name: "Read", tool_input: { file_path: "/x" }, tool_response: { ok: true }, tool_use_id: "t" + i }, L); times.push(Number(process.hrtime.bigint() - a) / 1e6); }
times.sort((a, b) => a - b);
check("median hook time under 250 ms", times[12] < 250, `median ${times[12].toFixed(0)} ms, p90 ${times[22].toFixed(0)} ms`);

// 7. Witness round trip against the real witness server, run locally.
const seed = crypto.randomBytes(32).toString("hex");
const srv = spawn(process.execPath, [path.join(ROOT, "witness/server.mjs")], { env: { ...process.env, PORT: "18787", WITNESS_ED25519_SEED: seed }, stdio: ["ignore", "pipe", "pipe"] });
await new Promise(r => srv.stdout.once("data", r));
// A second witness with its own key, to test requiring more than one.
const seed2 = crypto.randomBytes(32).toString("hex");
const srv2 = spawn(process.execPath, [path.join(ROOT, "witness/server.mjs")], { env: { ...process.env, PORT: "18788", WITNESS_ED25519_SEED: seed2 }, stdio: ["ignore", "pipe", "pipe"] });
await new Promise(r => srv2.stdout.once("data", r));
const W = tmp("hive-wit-"), WS = "wit-" + crypto.randomUUID();
const wev = events.slice(0, 10);
for (const ev of wev) spawnSync(process.execPath, [REC], { input: JSON.stringify({ ...ev, session_id: WS }), env: { ...process.env, HIVE_RECORDER_DIR: W, HIVE_WITNESS_URL: "http://127.0.0.1:18787/v1/witness,http://127.0.0.1:18788/v1/witness", HIVE_TSA_URL: process.env.HIVE_TEST_TSA || "http://timestamp.digicert.com" } });
const wfile = path.join(W, "records", WS + ".jsonl").replace(/\.jsonl$/, ".witness.jsonl");
// Each witness signs at the start, before every tool call and at every seal.
const want = 2 * (1 + wev.filter(e => e.hook_event_name === "PreToolUse").length + wev.filter(e => e.hook_event_name === "Stop" || e.hook_event_name === "SessionEnd").length);
const tfile = wfile.replace(/\.witness\.jsonl$/, ".timestamps.jsonl");
const nlines = f => fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean).length : 0;
for (let i = 0; i < 150 && (nlines(wfile) < want || nlines(tfile) < 1); i++) await new Promise(r => setTimeout(r, 100));
const wkey = (await (await fetch("http://127.0.0.1:18787/v1/witness/key")).json()).witness_key;
const wkey2 = (await (await fetch("http://127.0.0.1:18788/v1/witness/key")).json()).witness_key;
const wrec = path.join(W, "records", WS + ".jsonl");
const wr = verifyFile(wrec, { witnessKeys: [wkey, wkey2] });
check("witness: signed at the start, before every tool call and at every seal, by both witnesses", wr.ok && wr.gates.WITNESS === "PASS" && wr.witnessed.length === want && wr.witness_coverage.witnesses === 2, wr.witnessed.length + " of " + want + " " + JSON.stringify(wr.first_failure));
check("witness: every line, up to the last, is covered (--full-coverage)", verifyFile(wrec, { witnessKeys: [wkey, wkey2], fullCoverage: true }).ok);
check("witness: two different witnesses required and present (--min-witnesses 2)", verifyFile(wrec, { witnessKeys: [wkey, wkey2], minWitnesses: 2 }).ok);
const only1 = verifyFile(wrec, { witnessKeys: [wkey], minWitnesses: 2, witness: (() => { const f = wrec + ".one"; fs.writeFileSync(f, fs.readFileSync(wfile, "utf8").split("\n").filter(l => l && JSON.parse(l).witness_key === wkey).join("\n") + "\n"); return f; })() });
check("witness: only one of two required witnesses is rejected at WITNESS", !only1.ok && only1.first_failure.gate === "WITNESS", only1.first_failure && only1.first_failure.why);
check("witness: statements signed within 30 s of each line pass --max-lag 30", verifyFile(wrec, { witnessKeys: [wkey, wkey2], maxLag: 30 }).ok);
const late = verifyFile(wrec, { witnessKeys: [wkey, wkey2], maxLag: -1 });
check("witness: a statement signed later than allowed is rejected (a record rebuilt later gets late statements)", !late.ok && late.first_failure.gate === "WITNESS" && /witnessed/.test(late.first_failure.why), late.first_failure && late.first_failure.why);
const nows = verifyFile(wrec, { witness: wrec + ".none", requireWitness: true });
check("witness: a record handed over without its statements fails when witnessing is required", !nows.ok && nows.first_failure.gate === "WITNESS");
check("timestamp: RFC 3161 tokens from a public authority verify with openssl and cover heads in the chain", wr.gates.TIMESTAMP === "PASS" && wr.timestamps.length >= 1, JSON.stringify(wr.timestamps) + " " + nlines(tfile));
{
  // A timestamp whose authority time is an hour from the line it covers: what fresh tokens on a back-dated rebuild look like.
  const L = fs.readFileSync(wrec, "utf8").trim().split("\n").map(l => JSON.parse(l));
  const fake = [{ count: 3, head: L[2].hash, ok: true, tsa: "test", gen_time: new Date(Date.parse(L[2].t) + 3600e3).toISOString() }];
  const r = verifyRecord(L, nodeCrypto, { timestamps: fake, maxLagSec: 10 });
  check("timestamp: an authority time far from the line's own time is rejected at TIMESTAMP", !r.ok && r.first_failure.gate === "TIMESTAMP", r.first_failure && r.first_failure.why);
}
srv2.kill();
const bad = await fetch("http://127.0.0.1:18787/v1/witness", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ recorder_key: "x".repeat(43), session_fp: "0".repeat(64), count: 3, head: "0".repeat(64), prompt: "hello" }) });
check("witness refuses any field beyond the four fingerprints", bad.status === 400);

// 8. Tamper cases. Each must be rejected, with the expected first gate.
const T = path.join(ROOT, "examples/tamper"); fs.mkdirSync(T, { recursive: true });
for (const f of fs.readdirSync(T)) fs.unlinkSync(path.join(T, f));
const base = fs.readFileSync(path.join(W, "records", WS + ".jsonl"), "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const wst = fs.readFileSync(wfile, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
const sk = crypto.createPrivateKey(fs.readFileSync(path.join(W, "keys/recorder-ed25519.pem")));
const resign = (lines, key = sk) => { let prev = "0".repeat(64); return lines.map((l, i) => { const b = { ...body(l), seq: i, prev }; const c = canon(b); const h = crypto.createHash("sha256").update(c).digest("hex"); prev = h; return { ...b, hash: h, sig: crypto.sign(null, Buffer.from(c), key).toString("base64url") }; }); };
const findSeq = pred => base.findIndex(pred);
const iRefund = findSeq(l => l.tool && l.tool.use_id === "toolu_03");
const iFail = findSeq(l => l.event === "PostToolUseFailure");
const other = crypto.generateKeyPairSync("ed25519").privateKey;
const otherPub = crypto.createPublicKey(other).export({ format: "jwk" }).x;
const cases = [
  ["refund-call-deleted", "The refund attempt is deleted from the record", "CHAIN_ORDER", () => base.filter((_, i) => i !== iRefund)],
  ["failure-rewritten", "The failed test run is edited to look like success", "ENTRY_HASH", () => base.map((l, i) => i === iFail ? { ...l, event: "PostToolUse" } : l)],
  ["tool-renamed", "A Bash call is relabelled as a harmless Read", "ENTRY_HASH", () => base.map((l, i) => i === iRefund ? { ...l, tool: { ...l.tool, name: "Read" } } : l)],
  ["time-moved", "A tool call's time is moved earlier", "ENTRY_HASH", () => base.map((l, i) => i === iRefund ? { ...l, t: "2020-01-01T00:00:00.000Z" } : l)],
  ["lines-swapped", "Two tool calls swap places", "CHAIN_ORDER", () => { const b = base.slice(); [b[3], b[4]] = [b[4], b[3]]; return b; }],
  ["fingerprint-swapped", "The refund's input fingerprint is replaced with a harmless one", "ENTRY_HASH", () => base.map((l, i) => i === iRefund ? { ...l, fp: { ...l.fp, input: base[5].fp.input } } : l)],
  ["signature-forged", "A line is re-signed with a different key but keeps the original key id", "SIGNATURE", () => { const b = base.slice(); const x = { ...body(b[2]) }; const c = canon(x); b[2] = { ...x, hash: crypto.createHash("sha256").update(c).digest("hex"), sig: crypto.sign(null, Buffer.from(c), other).toString("base64url") }; return b; }],
  ["seal-moved", "A seal is edited to cover fewer lines", "ENTRY_HASH", () => base.map(l => l.event === "Seal" ? { ...l, count: l.count - 1 } : l)],
  ["rewritten-dropped-refund", "Whole record rebuilt and re-signed with the recorder's own key, refund removed", "WITNESS", () => resign(base.filter((_, i) => i !== iRefund).map(l => l.event === "Seal" ? { ...l } : l)).map((l, i, a) => l.event === "Seal" ? l : l)],
  ["rewritten-other-key", "Whole record rebuilt and signed with a different key", "KEY_PIN", () => resign(base.map((l, i) => i === 0 ? { ...l, public_key: otherPub } : l), other)],
];
let rejected = 0;
const manifest = [];
for (const [id, what, gate, make] of cases) {
  let lines = make();
  // For rebuilt records, fix up seals so the rebuild is internally consistent, which is the strongest forgery.
  if (id.startsWith("rewritten")) {
    const key = id === "rewritten-other-key" ? other : sk;
    let fixed = []; let prev = "0".repeat(64);
    for (const [i, l0] of lines.entries()) { const l = { ...body(l0), seq: i, prev }; if (l.event === "Seal") { l.count = i; l.head = prev; } const c = canon(l); const h = crypto.createHash("sha256").update(c).digest("hex"); fixed.push({ ...l, hash: h, sig: crypto.sign(null, Buffer.from(c), key).toString("base64url") }); prev = h; }
    lines = fixed;
  }
  const f = path.join(T, id + ".jsonl");
  fs.writeFileSync(f, lines.map(l => JSON.stringify(l)).join("\n") + "\n");
  fs.writeFileSync(f.replace(/\.jsonl$/, ".witness.jsonl"), wst.map(l => JSON.stringify(l)).join("\n") + "\n");
  const pin = id === "rewritten-other-key" ? JSON.parse(fs.readFileSync(path.join(W, "keys/key.json"))).public_key : undefined;
  const r = verifyFile(f, { key: pin, witnessKey: wkey });
  const ok = !r.ok && r.first_failure && r.first_failure.gate === gate;
  if (ok) rejected++;
  manifest.push({ id, what, expected: gate, got: r.first_failure && r.first_failure.gate, why: r.first_failure && r.first_failure.why });
  check(`tamper ${id}: rejected at ${gate}`, ok, r.first_failure ? r.first_failure.gate + ", " + r.first_failure.why : "accepted");
}
fs.writeFileSync(path.join(T, "MANIFEST.json"), JSON.stringify(manifest, null, 2));
srv.kill();


// ---------- admission, scope check and the optional ML-DSA-65 signature ----------
{
  const { hostsIn } = await import("../plugins/hive-recorder/scripts/record.mjs");
  const { ml_dsa65 } = await import("../plugins/hive-recorder/scripts/vendor/ml-dsa-65.mjs");
  const hs = hostsIn("git clone git@github.com:a/b.git && curl -s https://HuggingFace.co/api/x && ssh -p 22 deploy@prod.acme.io ls");
  check("hosts read from a Bash command: git, URL and ssh", ["github.com", "huggingface.co", "prod.acme.io"].every(h => hs.includes(h)), hs.join(" "));
  const proj = tmp("hive-proj-"); fs.mkdirSync(path.join(proj, ".claude"));
  const policy = { purpose: "Fix the invoice tax bug using only this repository. PURPOSE-TEXT-SHOULD-NOT-APPEAR", tools: ["Read", "Edit", "Bash", "Glob", "Grep", "WebFetch"], paths: ["**"], hosts: ["registry.npmjs.org"], labels: { sandbox: "test-sandbox" } };
  fs.writeFileSync(path.join(proj, ".claude/hive-admission.json"), JSON.stringify(policy));
  const AD = tmp("hive-adm-"), AS = "adm-" + crypto.randomUUID();
  const ac = { session_id: AS, transcript_path: "/x/" + AS + ".jsonl", cwd: proj, permission_mode: "default" };
  const aev = [
    { ...ac, hook_event_name: "SessionStart", source: "startup" },
    { ...ac, hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: path.join(proj, "src/invoice.js") }, tool_use_id: "a1" },
    { ...ac, hook_event_name: "PostToolUse", tool_name: "Read", tool_input: { file_path: path.join(proj, "src/invoice.js") }, tool_response: { ok: 1 }, tool_use_id: "a1" },
    { ...ac, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "curl -s https://huggingface.co/api/models?limit=1" }, tool_use_id: "a2" },
    { ...ac, hook_event_name: "PostToolUse", tool_name: "Bash", tool_input: { command: "curl -s https://huggingface.co/api/models?limit=1" }, tool_response: { stdout: "[]" }, tool_use_id: "a2" },
    { ...ac, hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/etc/passwd" }, tool_use_id: "a3" },
    { ...ac, hook_event_name: "PreToolUse", tool_name: "WebFetch", tool_input: { url: "https://registry.npmjs.org/left-pad", prompt: "version" }, tool_use_id: "a4" },
    { ...ac, hook_event_name: "PreToolUse", tool_name: "Write", tool_input: { file_path: path.join(proj, "notes.md"), content: "x" }, tool_use_id: "a5" },
    { ...ac, hook_event_name: "Stop", last_assistant_message: "done" },
  ];
  const ptimes = [];
  for (const e of aev) { const t = process.hrtime.bigint(); hook(e, AD, { HIVE_PQ: "1" }); ptimes.push(Number(process.hrtime.bigint() - t) / 1e6); }
  ptimes.sort((a, b) => a - b);
  const af = path.join(AD, "records", AS + ".jsonl");
  const ar = verifyFile(af);
  check("admission session verifies, ML-DSA-65 and admission gates pass", ar.ok && ar.gates.PQ_SIGNATURE === "PASS" && ar.gates.ADMISSION === "PASS", JSON.stringify(ar.gates));
  const alines = fs.readFileSync(af, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
  check("the admission is line 1, signed before any tool call", alines[1].event === "Admission" && alines[1].scope.hosts[0] === "registry.npmjs.org");
  const out = ar.summary.outside_admission;
  check("outside admission: the huggingface.co call, /etc/passwd and the Write tool, nothing else", out.length === 3 && out[0].outside.hosts[0] === "huggingface.co" && out[0].ran && out[1].outside.paths[0] === "/etc/passwd" && !out[1].ran && out[2].outside.tool, JSON.stringify(out.map(o => o.outside)));
  check("purpose text never enters the record", !fs.readFileSync(af, "utf8").includes("PURPOSE-TEXT"));
  const cli = spawnSync(process.execPath, [path.join(ROOT, "plugins/hive-recorder/scripts/verify.mjs"), af], { encoding: "utf8" });
  check("verifier exits 3 when the record holds but calls fell outside the admission", cli.status === 3 && cli.stdout.includes("OUTSIDE ADMISSION"), "exit " + cli.status);
  const pf = path.join(AD, "policy.json"); fs.writeFileSync(pf, JSON.stringify(policy));
  check("--admission with the policy the reviewer was given passes", verifyFile(af, { admission: pf }).ok);
  fs.writeFileSync(pf, JSON.stringify({ ...policy, hosts: ["registry.npmjs.org", "huggingface.co"] }));
  const aw = verifyFile(af, { admission: pf });
  check("--admission with a different policy is rejected at ADMISSION", !aw.ok && aw.first_failure.gate === "ADMISSION");
  const stripped = alines.map((l, i) => i === 4 ? (({ sig_pq, ...r }) => r)(l) : l);
  const sf = path.join(AD, "stripped.jsonl"); fs.writeFileSync(sf, stripped.map(l => JSON.stringify(l)).join("\n") + "\n");
  const sr = verifyFile(sf, { witness: sf + ".none" });
  check("ML-DSA-65 signature removed from one line: rejected at PQ_SIGNATURE", !sr.ok && sr.first_failure.gate === "PQ_SIGNATURE", sr.first_failure && sr.first_failure.why);
  // The recorder's own keys re-sign a line that claims the huggingface.co call was inside scope.
  const ask = crypto.createPrivateKey(fs.readFileSync(path.join(AD, "keys/recorder-ed25519.pem")));
  const apq = ml_dsa65.keygen(Uint8Array.from(Buffer.from(fs.readFileSync(path.join(AD, "keys/recorder-ml-dsa-65.seed"), "utf8").trim(), "hex")));
  let prev = "0".repeat(64);
  const lie = alines.map((l0, i) => { const l = { ...body(l0), seq: i, prev }; if (l.tool && l.tool.use_id === "a2" && l.scope) l.scope = { ...l.scope, outside: { tool: false, paths: [], hosts: [] } }; if (l.event === "Seal") { l.count = i; l.head = prev; } const c = canon(l); const h = crypto.createHash("sha256").update(c).digest("hex"); prev = h; return { ...l, hash: h, sig: crypto.sign(null, Buffer.from(c), ask).toString("base64url"), sig_pq: Buffer.from(ml_dsa65.sign(Buffer.from(c), apq.secretKey)).toString("base64url") }; });
  const lf = path.join(AD, "lie.jsonl"); fs.writeFileSync(lf, lie.map(l => JSON.stringify(l)).join("\n") + "\n");
  const lr = verifyFile(lf, { witness: lf + ".none" });
  check("scope check rewritten and fully re-signed with both recorder keys: rejected at ADMISSION", !lr.ok && lr.first_failure.gate === "ADMISSION", lr.first_failure && lr.first_failure.why);
  check("median hook time with ML-DSA-65 under 400 ms", ptimes[4] < 400, `median ${ptimes[4].toFixed(0)} ms`);
}

// 11. Licensed data through MCP tools: the admission lists datasets, and a pull outside them is flagged.
{
  const P = tmp("hive-ds-proj-"), DD = tmp("hive-ds-"), DS = "ds-" + crypto.randomUUID();
  fs.mkdirSync(path.join(P, ".claude"));
  const pol = { purpose: "EOD futures settlement check", tools: ["mcp__market-data__*"], paths: ["**"], hosts: [], datasets: ["futures.brent.*", "futures.wti.eod"] };
  fs.writeFileSync(path.join(P, ".claude/hive-admission.json"), JSON.stringify(pol));
  const evs = [
    { hook_event_name: "SessionStart", source: "startup" },
    { hook_event_name: "PreToolUse", tool_name: "mcp__market-data__get_eod", tool_use_id: "d1", tool_input: { dataset: "futures.brent.eod", date: "2026-10-09" } },
    { hook_event_name: "PostToolUse", tool_name: "mcp__market-data__get_eod", tool_use_id: "d1", tool_input: { dataset: "futures.brent.eod", date: "2026-10-09" }, tool_response: { settle: 1 } },
    { hook_event_name: "PreToolUse", tool_name: "mcp__market-data__get_records", tool_use_id: "d2", tool_input: { dataset: "mortgage.loan-level", limit: 100 } },
    { hook_event_name: "PostToolUse", tool_name: "mcp__market-data__get_records", tool_use_id: "d2", tool_input: { dataset: "mortgage.loan-level", limit: 100 }, tool_response: { rows: [] } },
    { hook_event_name: "Stop", last_assistant_message: "done" },
  ];
  for (const ev of evs) spawnSync(process.execPath, [REC], { input: JSON.stringify({ ...ev, session_id: DS, cwd: P }), env: { ...process.env, HIVE_RECORDER_DIR: DD, HIVE_WITNESS_URL: "off", HIVE_TSA_URL: "off" } });
  const pf = path.join(DD, "pol.json"); fs.writeFileSync(pf, JSON.stringify(pol));
  const dr = verifyFile(path.join(DD, "records", DS + ".jsonl"), { admission: pf });
  const o = dr.ok && dr.summary.outside_admission;
  check("datasets: a pull from a dataset outside the admission is flagged, one inside is not", dr.ok && o.length === 1 && o[0].outside.datasets[0] === "mortgage.loan-level", JSON.stringify(o));
  const raw = fs.readFileSync(path.join(DD, "records", DS + ".jsonl"), "utf8");
  check("datasets: the record names the dataset but keeps none of the data", raw.includes("mortgage.loan-level") && !raw.includes("settle"));
}

// 12. A witness that is slow to answer (asleep, far away): the hook stops waiting, the statement still arrives.
{
  const slow = http.createServer((q, r) => { let b = ""; q.on("data", c => b += c); q.on("end", () => setTimeout(() => { const j = JSON.parse(b); r.writeHead(200, { "content-type": "application/json" }); r.end(JSON.stringify({ v: "hive.agent-action-witness/1", ...j, witnessed_at: new Date().toISOString(), witness_key: "x".repeat(43), sig: "slow" })); }, 1500)); }).listen(18791);
  const SD = tmp("hive-slow-"), SS = "slow-" + crypto.randomUUID();
  const t0 = Date.now();
  spawnSync(process.execPath, [REC], { input: JSON.stringify({ hook_event_name: "SessionStart", source: "startup", session_id: SS, cwd: "/tmp" }), env: { ...process.env, HIVE_RECORDER_DIR: SD, HIVE_WITNESS_URL: "http://127.0.0.1:18791/v1/witness", HIVE_TSA_URL: "off", HIVE_WITNESS_WAIT_MS: "300" } });
  const took = Date.now() - t0;
  const wf = path.join(SD, "records", SS + ".witness.jsonl");
  for (let i = 0; i < 60 && !fs.existsSync(wf); i++) await new Promise(r => setTimeout(r, 100));
  check("slow witness: the hook returns after its wait, and the statement still arrives afterwards", took < 1400 && fs.existsSync(wf), took + " ms");
  slow.close();
}

// 10. Witness memory (needs Postgres: HIVE_TEST_PG=postgres://user:pass@host/db). The witness keeps every
// statement it signs and a reviewer asks it directly, so withholding or rebuilding afterwards is caught.
if (process.env.HIVE_TEST_PG) {
  const { fetchMemory } = await import("../plugins/hive-recorder/scripts/verify.mjs");
  const mseed = crypto.randomBytes(32).toString("hex");
  const ms = spawn(process.execPath, [path.join(ROOT, "witness/server.mjs")], { env: { ...process.env, PORT: "18789", WITNESS_ED25519_SEED: mseed, DATABASE_URL: process.env.HIVE_TEST_PG, DATABASE_SSL: "off" }, stdio: ["ignore", "pipe", "pipe"] });
  await new Promise(r => ms.stdout.once("data", r));
  const MU = "http://127.0.0.1:18789";
  const MW = tmp("hive-mem-"), MS = "mem-" + crypto.randomUUID();
  const mev = events.slice(0, 10);
  for (const ev of mev) spawnSync(process.execPath, [REC], { input: JSON.stringify({ ...ev, session_id: MS }), env: { ...process.env, HIVE_RECORDER_DIR: MW, HIVE_WITNESS_URL: MU + "/v1/witness", HIVE_TSA_URL: "off", HIVE_WITNESS_WAIT_MS: "3000" } });
  const mrec = path.join(MW, "records", MS + ".jsonl");
  const ml = fs.readFileSync(mrec, "utf8").trim().split("\n").map(l => JSON.parse(l));
  const mkey = (await (await fetch(MU + "/v1/witness/key")).json()).witness_key;
  const mem = await fetchMemory(ml, MU);
  const local = fs.readFileSync(mrec.replace(/\.jsonl$/, ".witness.jsonl"), "utf8").trim().split("\n").length;
  check("memory: the witness remembers every statement it signed for the session", mem.statements.length === local && local >= 3, mem.statements.length + " remembered, " + local + " saved locally");
  const ok1 = verifyFile(mrec, { witness: mrec + ".none", witnessKey: mkey, memory: mem, requireMemory: true, fullCoverage: true, maxLag: 10 });
  check("memory: a record handed over with no statements at all passes against what the witness remembers", ok1.ok && ok1.witness_coverage.unwitnessed_tail === 0, JSON.stringify(ok1.first_failure));
  const cut = mrec.replace(/\.jsonl$/, ".cut.jsonl");
  fs.writeFileSync(cut, ml.slice(0, ml.length - 3).map(l => JSON.stringify(l)).join("\n") + "\n");
  const r2 = verifyFile(cut, { witness: mrec + ".none", witnessKey: mkey, memory: mem, requireMemory: true });
  check("memory: the end cut off, statements withheld: rejected, the witness remembers more lines", !r2.ok && r2.first_failure.gate === "WITNESS" && /has only/.test(r2.first_failure.why), r2.first_failure && r2.first_failure.why);
  const msk = crypto.createPrivateKey(fs.readFileSync(path.join(MW, "keys/recorder-ed25519.pem")));
  const drop = ml.findIndex(l => l.event === "PreToolUse");
  const rebuilt = (() => { let prev = "0".repeat(64); return ml.filter((l, i) => i !== drop && i !== drop + 1).map((l, i) => { const b = { ...body(l), seq: i, prev }; if (b.event === "Seal") { b.count = i; b.head = prev; } const cc = canon(b); const h = crypto.createHash("sha256").update(cc).digest("hex"); prev = h; return { ...b, hash: h, sig: crypto.sign(null, Buffer.from(cc), msk).toString("base64url") }; }); })();
  const rb = mrec.replace(/\.jsonl$/, ".rebuilt.jsonl");
  fs.writeFileSync(rb, rebuilt.map(l => JSON.stringify(l)).join("\n") + "\n");
  // Ask the witness for fresh statements on the rebuilt heads, as a lab could, and hand only those over.
  const fresh = [];
  const sreq = (key, count, head, k = msk) => { const q = { recorder_key: key, session_fp: crypto.createHash("sha256").update(MS).digest("hex"), count, head }; q.req_sig = crypto.sign(null, Buffer.from(canon(q)), k).toString("base64url"); return q; };
  // Poisoning: someone without the recorder key tries to add a history to this session.
  const junk = { recorder_key: ml[0].public_key, session_fp: crypto.createHash("sha256").update(MS).digest("hex"), count: 2, head: "ab".repeat(32) };
  const pj1 = await fetch(MU + "/v1/witness", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(junk) });
  const pj2 = await fetch(MU + "/v1/witness", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sreq(ml[0].public_key, 2, "ab".repeat(32), crypto.generateKeyPairSync("ed25519").privateKey)) });
  const afterJunk = verifyFile(mrec, { witness: mrec + ".none", witnessKey: mkey, memory: await fetchMemory(ml, MU), requireMemory: true });
  check("memory: nobody without the recorder key can add to a session's memory", pj1.headers.get("x-witness-remembered") === "false" && pj2.status === 400 && afterJunk.ok, pj1.headers.get("x-witness-remembered") + " " + pj2.status + " " + JSON.stringify(afterJunk.first_failure));
  // A lab holding the recorder key rebuilds and asks the witness again, with properly signed requests.
  for (const l of rebuilt.filter(l => ["SessionStart", "PreToolUse", "Seal"].includes(l.event))) fresh.push(await (await fetch(MU + "/v1/witness", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(sreq(rebuilt[0].public_key, l.seq + 1, l.hash)) })).json());
  fs.writeFileSync(rb.replace(/\.jsonl$/, ".witness.jsonl"), fresh.map(x => JSON.stringify(x)).join("\n") + "\n");
  const r3a = verifyFile(rb, { witnessKey: mkey });
  const r3 = verifyFile(rb, { witnessKey: mkey, memory: await fetchMemory(rebuilt, MU), requireMemory: true });
  check("memory: a call deleted, re-signed with the recorder key, fresh signed statements obtained: passes on its own statements, rejected once the witness is asked", r3a.ok && !r3.ok && r3.first_failure.gate === "WITNESS", r3.first_failure && r3.first_failure.why);
  const r4 = verifyFile(mrec, { memory: { statements: [], from: MU }, requireMemory: true });
  check("memory: a session the witness never saw fails when memory is required", !r4.ok && /no memory/.test(r4.first_failure.why));
  const bad = await fetch(MU + "/v1/witness/statements?recorder_key=x&session_fp=y");
  check("memory: the witness only answers for a full recorder key and session fingerprint", bad.status === 400);
  ms.kill();
} else console.log("skip witness memory tests (set HIVE_TEST_PG)");

// 9. Service mode: recorderd holds the keys and the record; the hook holds only the fingerprint key.
{
  const RD = tmp("hive-rd-"), HD = tmp("hive-hook-"), SS = "svc-" + crypto.randomUUID();
  const pol = path.join(RD, "admission.json");
  fs.writeFileSync(pol, JSON.stringify({ purpose: "test", tools: ["Read", "Bash", "Edit"], paths: ["**"], hosts: ["registry.npmjs.org"] }));
  const d = spawn(process.execPath, [path.join(ROOT, "plugins/hive-recorder/scripts/recorderd.mjs")], { env: { ...process.env, HIVE_RECORDER_DIR: RD, HIVE_ADMISSION: pol, HIVE_RECORDERD_PORT: "18790", HIVE_WITNESS_URL: "off", HIVE_TSA_URL: "off" }, stdio: ["ignore", "pipe", "pipe"] });
  await new Promise(r => d.stdout.once("data", r));
  const svcEvents = [
    { hook_event_name: "SessionStart", source: "startup", cwd: "/tmp/p" },
    { hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "t1", tool_input: { command: "curl -s https://huggingface.co/api/x" }, cwd: "/tmp/p" },
    { hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "t1", tool_input: { command: "curl -s https://huggingface.co/api/x" }, tool_response: { stdout: "secret content" }, cwd: "/tmp/p" },
    { hook_event_name: "Stop", last_assistant_message: "done", cwd: "/tmp/p" },
  ];
  for (const ev of svcEvents) spawnSync(process.execPath, [REC], { input: JSON.stringify({ ...ev, session_id: SS }), env: { ...process.env, HIVE_RECORDER_DIR: HD, HIVE_RECORDER_URL: "http://127.0.0.1:18790" } });
  const sf = path.join(RD, "records", SS + ".jsonl");
  const sr = fs.existsSync(sf) ? verifyFile(sf, { admission: pol }) : { ok: false };
  check("service mode: the record and signing keys live with recorderd, the agent's side has neither", sr.ok && !fs.existsSync(path.join(HD, "records")) && !fs.existsSync(path.join(HD, "keys", "recorder-ed25519.pem")) && fs.existsSync(path.join(RD, "keys", "recorder-ed25519.pem")));
  check("service mode: recorderd signs its own admission as line 1 and flags the call outside it", sr.ok && sr.summary.admission && sr.summary.outside_admission.length === 1 && sr.summary.outside_admission[0].outside.hosts[0] === "huggingface.co");
  check("service mode: no content reaches recorderd", !fs.readFileSync(sf, "utf8").includes("secret content") && !fs.readFileSync(sf, "utf8").includes("huggingface.co/api"));
  const smug = await fetch("http://127.0.0.1:18790/v1/event", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ session_id: SS, desc: { event: "PostToolUse", tool_output: "secret" } }) });
  check("service mode: recorderd refuses a description carrying any field beyond fingerprints and names", smug.status === 400);
  d.kill();
}

// Save the witnessed session as the example record.
const E = path.join(ROOT, "examples");
fs.copyFileSync(path.join(W, "records", WS + ".jsonl"), path.join(E, "session.jsonl"));
fs.copyFileSync(wfile, path.join(E, "session.witness.jsonl"));
fs.writeFileSync(path.join(E, "keys.json"), JSON.stringify({ recorder_key: JSON.parse(fs.readFileSync(path.join(W, "keys/key.json"))).public_key, witness_key: wkey, note: "Test keys from tests/run.mjs. The witness here ran locally with a throwaway key." }, null, 2));

const passed = results.filter(r => r.ok).length;
console.log(`\n${passed} of ${results.length} checks passed. ${rejected} of ${cases.length} tamper cases rejected.`);
fs.writeFileSync(path.join(ROOT, "tests/RESULTS.txt"), results.map(r => (r.ok ? "ok   " : "FAIL ") + r.name + (r.detail ? "  " + r.detail : "")).join("\n") + `\n\n${passed} of ${results.length} checks passed. ${rejected} of ${cases.length} tamper cases rejected.\nNode ${process.version}, ${os.platform()} ${os.arch()}, ${new Date().toISOString()}\n`);
process.exitCode = passed === results.length ? 0 : 1;
