// Test suite for the Hive recorder. Runs the real hook script as Claude Code would:
// one process per event, JSON on stdin, exit code and stdout checked.
//   node tests/run.mjs
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verifyFile } from "../plugins/hive-recorder/scripts/verify.mjs";
import { canon, body } from "../plugins/hive-recorder/scripts/core.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REC = path.join(ROOT, "plugins/hive-recorder/scripts/record.mjs");
const results = [];
const check = (name, ok, detail = "") => { results.push({ name, ok: !!ok, detail }); console.log((ok ? "ok   " : "FAIL ") + name + (detail ? "  " + detail : "")); };
const tmp = p => fs.mkdtempSync(path.join(os.tmpdir(), p));

function hook(ev, dir, extraEnv = {}) {
  const r = spawnSync(process.execPath, [REC], { input: JSON.stringify(ev), env: { ...process.env, HIVE_RECORDER_DIR: dir, HIVE_WITNESS_URL: "off", ...extraEnv }, encoding: "utf8" });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function hookAsync(ev, dir) {
  return new Promise(res => { const p = spawn(process.execPath, [REC], { env: { ...process.env, HIVE_RECORDER_DIR: dir, HIVE_WITNESS_URL: "off" } }); let out = ""; p.stdout.on("data", d => out += d); p.on("close", code => res({ code, out })); p.stdin.end(JSON.stringify(ev)); });
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
const rg = spawnSync(process.execPath, [REC], { input: "not json", env: { ...process.env, HIVE_RECORDER_DIR: tmp("hive-bad-"), HIVE_WITNESS_URL: "off" }, encoding: "utf8" });
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
const W = tmp("hive-wit-"), WS = "wit-" + crypto.randomUUID();
for (const ev of events.slice(0, 10)) spawnSync(process.execPath, [REC], { input: JSON.stringify({ ...ev, session_id: WS }), env: { ...process.env, HIVE_RECORDER_DIR: W, HIVE_WITNESS_URL: "http://127.0.0.1:18787/v1/witness" } });
const wfile = path.join(W, "records", WS + ".witness.jsonl");
for (let i = 0; i < 50 && !fs.existsSync(wfile); i++) await new Promise(r => setTimeout(r, 100));
const wkey = (await (await fetch("http://127.0.0.1:18787/v1/witness/key")).json()).witness_key;
const wr = verifyFile(path.join(W, "records", WS + ".jsonl"), { witnessKey: wkey });
check("witness: statement saved, verifies against the pinned witness key", wr.ok && wr.gates.WITNESS === "PASS" && wr.witnessed.length === 1, JSON.stringify(wr.gates));
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

// Save the witnessed session as the example record.
const E = path.join(ROOT, "examples");
fs.copyFileSync(path.join(W, "records", WS + ".jsonl"), path.join(E, "session.jsonl"));
fs.copyFileSync(wfile, path.join(E, "session.witness.jsonl"));
fs.writeFileSync(path.join(E, "keys.json"), JSON.stringify({ recorder_key: JSON.parse(fs.readFileSync(path.join(W, "keys/key.json"))).public_key, witness_key: wkey, note: "Test keys from tests/run.mjs. The witness here ran locally with a throwaway key." }, null, 2));

const passed = results.filter(r => r.ok).length;
console.log(`\n${passed} of ${results.length} checks passed. ${rejected} of ${cases.length} tamper cases rejected.`);
fs.writeFileSync(path.join(ROOT, "tests/RESULTS.txt"), results.map(r => (r.ok ? "ok   " : "FAIL ") + r.name + (r.detail ? "  " + r.detail : "")).join("\n") + `\n\n${passed} of ${results.length} checks passed. ${rejected} of ${cases.length} tamper cases rejected.\nNode ${process.version}, ${os.platform()} ${os.arch()}, ${new Date().toISOString()}\n`);
process.exitCode = passed === results.length ? 0 : 1;
