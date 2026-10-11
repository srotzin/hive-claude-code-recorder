// Derived-figure split across two vendors, on a real Claude Code session (examples/claude-code-cross-vendor).
// Each vendor checks its own input with its own log, its kept bodies and its own copy of the session; an auditor
// with both openings checks the arithmetic; the statement is checked against the public log.
import fs from "node:fs";
import crypto from "node:crypto";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";
import * as L from "../plugins/hive-recorder/scripts/log-check.mjs";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";
import { checkMyInput, checkArithmetic } from "../moat/split.mjs";
const E = new URL("../examples/claude-code-cross-vendor/", import.meta.url).pathname;
const jl = f => fs.readFileSync(E + f, "utf8").split("\n").filter(Boolean).map(JSON.parse), js = f => JSON.parse(fs.readFileSync(E + f, "utf8"));
const WKEY = "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE";
const cb = { sha256: u => new Uint8Array(crypto.createHash("sha256").update(u).digest()), verifyBytes: (pub, msg, sig) => { try { return crypto.verify(null, Buffer.from(msg), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub }, format: "jwk" }), Buffer.from(sig)); } catch { return false; } } };
const st = js("split.json"), V = ["market-data", "fx-data"];
const D = Object.fromEntries(V.map(v => [v, { copy: jl(`copies/session.${v}.jsonl`), vlog: jl(`vendor/${v}.deliveries.jsonl`), kept: jl(`vendor/${v}.kept-bodies.jsonl`), op: js(`firm/opening.${v}.json`) }]));
let pass = 0, all = 0; const ok = (n, b, d = "") => { all++; if (b) pass++; console.log((b ? "ok   " : "FAIL ") + n + (d ? "  " + d : "")); };
const refused = (n, r, step) => ok("refused: " + n, !r.ok && r.step === step, r.ok ? "accepted" : r.step + ", " + r.why);
const reh = s => ({ ...s, _sh: c.sha256hex(canon(s)) });
const bent = f => { const s = JSON.parse(JSON.stringify(st)); f(s); return s; };
const opFor = (s, o) => ({ ...o, split_sha256: c.sha256hex(canon(s)) });

for (const v of V) { const r = checkMyInput(st, D[v].op, D[v].copy, D[v].vlog, D[v].kept, c); ok(`${v} finds its own input in the figure`, r.ok, r.ok ? `${r.figure} = ${r.op}, its value ${r.my_value} is ${r.my_input}, delivery ${r.my_delivery_seq}` : r.step + ", " + r.why); }
ok("the auditor with both openings gets 84.12 / 1.084 = 77.60", checkArithmetic(st, V.map(v => D[v].op), c).ok);
const raw = JSON.stringify(st);
ok("the registered statement names no vendor and carries no value", !/market-data|fx-data|84\.12|1\.084/.test(raw));
ok("each vendor's copy hides the other vendor's step", D["market-data"].copy.find(l => l.seq === st.inputs[1].step_seq).redacted === true && D["fx-data"].copy.find(l => l.seq === st.inputs[0].step_seq).redacted === true);
const TS = fs.readFileSync(E + "split.transparent.cose"), t = C.decode(TS), emptied = C.encode(new C.Tag(18, [t.value[0], new Map(), t.value[2], t.value[3]]));
const rc = L.checkReceipt(t.value[1].get(394)[0], emptied, cb, { witnessPin: WKEY });
ok("the statement is on the public log with a valid receipt", rc.ok, rc.ok ? `leaf ${rc.leaf_index} of ${rc.tree_size}` : rc.why);
ok("the logged payload is the statement both vendors check", canon(JSON.parse(new TextDecoder().decode(t.value[2]))) === canon(st));

const M = D["market-data"], F = D["fx-data"];
refused("an opening with a different value", checkMyInput(st, { ...M.op, value: "84.13" }, M.copy, M.vlog, M.kept, c), "VALUE");
refused("the other vendor's opening", checkMyInput(st, F.op, M.copy, M.vlog, M.kept, c), "DELIVERY");
refused("an opening for an edited statement", checkMyInput(bent(s => { s.figure = "77.7"; }), M.op, M.copy, M.vlog, M.kept, c), "OPENING");
let s2 = bent(s => { s.inputs[0].delivery_fp = s.inputs[1].delivery_fp; }); refused("this vendor's input pointed at the other delivery", checkMyInput(s2, opFor(s2, M.op), M.copy, M.vlog, M.kept, c), "DELIVERY");
s2 = bent(s => { s.answer_fp = "0".repeat(64); }); refused("a statement about a different answer", checkMyInput(s2, opFor(s2, M.op), M.copy, M.vlog, M.kept, c), "ANSWER");
s2 = bent(s => { s.inputs[0].val_fp = s.inputs[1].val_fp; }); refused("a value fingerprint swapped", checkMyInput(s2, opFor(s2, M.op), M.copy, M.vlog, M.kept, c), "VALUE");
s2 = bent(s => { s.inputs[1] = { ...s.inputs[0] }; }); refused("both inputs credited to one vendor", checkMyInput(s2, opFor(s2, M.op), M.copy, M.vlog, M.kept, c), "SPLIT");
s2 = bent(s => { s.session_count = 13; }); refused("a statement that ends the session early", checkMyInput(s2, opFor(s2, M.op), M.copy, M.vlog, M.kept, c), "SESSION");
refused("a copy of a different session", checkMyInput(st, M.op, [{ ...M.copy[0], session: "another" }, ...M.copy.slice(1)], M.vlog, M.kept, c), "RECORD");
refused("a copy whose value fingerprints were edited", checkMyInput(st, M.op, M.copy.map(l => l.seq === st.inputs[0].step_seq ? { ...l, vals: [st.inputs[0].val_fp, "ab".repeat(32)] } : l), M.vlog, M.kept, c), "RECORD");
refused("a kept body that never carried the value", checkMyInput(st, M.op, M.copy, M.vlog, M.kept.map(k => ({ ...k, body: { ...k.body, settle: 80 } })), c), "VALUE");
s2 = bent(s => { s.figure = "77.7"; }); refused("the figure changed", checkArithmetic(s2, V.map(v => opFor(s2, D[v].op)), c), "ARITHMETIC");
s2 = bent(s => { s.op = "x * y"; }); refused("the operation changed", checkArithmetic(s2, V.map(v => opFor(s2, D[v].op)), c), "ARITHMETIC");
const ed = JSON.parse(new TextDecoder().decode(t.value[2])); ed.figure = "77.7";
const alt = C.encode(new C.Tag(18, [t.value[0], new Map(), new TextEncoder().encode(canon(ed)), t.value[3]]));
refused("the statement edited after it was logged", L.checkReceipt(t.value[1].get(394)[0], alt, cb, { witnessPin: WKEY }), "RECEIPT");
console.log(`\n${pass} of ${all} checks passed.`); process.exit(pass === all ? 0 : 1);
