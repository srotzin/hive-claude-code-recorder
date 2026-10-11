// examples/claude-code-gateway against the live witness and its public log.
//   node tests/gateway-live.mjs <stand-in vendor key .pem>   (not in the repository; only the re-signed tamper cases need it)
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { canon, checkMatch, checkDerived, checkDeliveries } from "../plugins/hive-recorder/scripts/core.mjs";
import * as L from "../plugins/hive-recorder/scripts/log-check.mjs";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const E = path.join(ROOT, "examples/claude-code-gateway");
const W = process.env.HIVE_WITNESS || "https://witness.thehiveryiq.com", WKEY = "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE";
const cb = { sha256: u => new Uint8Array(crypto.createHash("sha256").update(u).digest()), verifyBytes: (pub, msg, sig) => { try { return crypto.verify(null, Buffer.from(msg), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub }, format: "jwk" }), Buffer.from(sig)); } catch { return false; } } };
const vk = process.argv[2] ? crypto.createPrivateKey(fs.readFileSync(process.argv[2])) : null;
const rl = f => fs.readFileSync(path.join(E, f), "utf8").split("\n").filter(Boolean).map(JSON.parse);
const A = [rl("copies/session-1.market-data.jsonl"), rl("copies/session-2.market-data.jsonl")];
const ANS = [1, 2].map(i => fs.readFileSync(path.join(E, `answer-${i}.txt`), "utf8"));
const VL = rl("vendor/market-data.deliveries.jsonl"), VP = rl("vendor/market-data.delivered-bodies.jsonl");
const M = JSON.parse(fs.readFileSync(path.join(E, "copies/match.market-data.json"), "utf8"));
const COS = JSON.parse(fs.readFileSync(path.join(E, "cosigners.json"), "utf8"));
const TS = new Uint8Array(fs.readFileSync(path.join(E, "scitt/match.transparent.cose")));
const get = async (q, t) => { const r = await fetch(W + q); if (!r.ok) throw new Error(q + " " + r.status); return t === "text" ? r.text() : r.json(); };
const sfp = Ls => c.sha256hex(String(Ls[0].session));
const memory = {}, proofs = {};
for (const Ls of A) {
  memory[sfp(Ls)] = (await get("/v1/witness/statements?" + new URLSearchParams({ recorder_key: M.recorder_key, session_fp: sfp(Ls) }))).statements;
  proofs[sfp(Ls)] = await get("/v1/witness/log/proofs?" + new URLSearchParams({ recorder_key: M.recorder_key, session_fp: sfp(Ls) }));
}
const logMemory = (await get("/v1/witness/statements?" + new URLSearchParams({ recorder_key: M.vendor_key, session_fp: VL[0].log }))).statements;
const logProofs = await get("/v1/witness/log/proofs?" + new URLSearchParams({ recorder_key: M.vendor_key, session_fp: VL[0].log }));
const witnessSessions = (await get("/v1/witness/sessions?" + new URLSearchParams({ recorder_key: M.recorder_key, from: M.period.from, to: M.period.to }))).sessions;
const opts = { recorderPin: M.recorder_key, vendorPin: M.vendor_key, witnessPin: WKEY, memory, logMemory, witnessSessions };
const pin = { witnessPin: WKEY };
let ok = 0, all = 0;
const say = (name, good, d = "") => { all++; if (good) ok++; console.log((good ? "ok   " : "FAIL ") + name + (d ? "  " + d : "")); };

// Genuine.
const g = checkMatch(M, A, VL, c, opts);
say("the match holds: 3 matched, 1 delivered with no record, 0 recorded with no delivery", g.ok && g.matched === 3 && g.unrecorded === 1 && g.unmatched === 0, g.ok ? "" : g.step + " " + g.why);
const dv = checkDeliveries(VL, c, { vendorPin: M.vendor_key, witnessPin: WKEY, memory: logMemory, requireMemory: true });
say("every delivery the gateway logged was witnessed before it went out", dv.ok && dv.witnessed === VL.length, dv.ok ? dv.witnessed + " of " + VL.length : dv.why);
const d1 = checkDerived(A[0], ANS[0], VL, VP, "market-data", c), d2 = checkDerived(A[1], ANS[1], VL, VP, "market-data", c);
const ops = [...(d1.derived || []), ...(d2.derived || [])].map(x => x.figure + " " + x.op);
say("computed figures traced: spread, ratio, percent change, sum, share", ["4.77 difference", "1.06 ratio", "2.71 percent change", "1260000 sum", "20.16 share"].every(x => ops.includes(x)) && ops.length === 5, ops.join(", "));
for (const Ls of A) { const r = L.checkLogged(memory[sfp(Ls)], proofs[sfp(Ls)], cb, pin); say("session " + Ls[0].session.slice(0, 8) + ": every witness statement proves into the public log", r.ok, r.ok ? r.logged + " statements" : r.why); }
const rv = L.checkLogged(logMemory, logProofs, cb, pin);
say("the vendor's delivery log: every witness statement proves into the public log", rv.ok, rv.ok ? rv.logged + " statements" : rv.why);
const cosR = await get("/v1/witness/log/cosignatures");
const cpSize = Math.max(...cosR.cosignatures.filter(x => COS.cosigners.some(w => w.key === x.cosigner_key)).map(x => x.tree_size));
const cp = await get("/v1/witness/log/checkpoint?tree_size=" + cpSize, "text");
const ck = L.checkCheckpoint(cp, cb, { origin: COS.origin, logKey: WKEY, cosigners: COS.cosigners, quorum: 2 });
say("the latest cosigned checkpoint carries both outside cosignatures", ck.ok && ck.cosigned.length === 2, ck.ok ? "size " + ck.tree_size : ck.why);
const t = C.decode(TS), emptied = C.encode(new C.Tag(18, [t.value[0], new Map(), t.value[2], t.value[3]]));
const rc = L.checkReceipt(t.value[1].get(394)[0], emptied, cb, pin);
say("the match, registered as a SCITT Signed Statement, has a valid RFC 9942 receipt", rc.ok, rc.ok ? "leaf " + rc.leaf_index + " of " + rc.tree_size : rc.why);
const ssPayload = JSON.parse(new TextDecoder().decode(t.value[2]));
say("the registered statement is this exact match", canon(ssPayload) === canon(M));
if (rc.ok && rc.tree_size <= ck.tree_size) {
  const hs = await get("/v1/witness/log/head?tree_size=" + rc.tree_size), he = await get("/v1/witness/log/head?tree_size=" + ck.tree_size);
  const cons = await get(`/v1/witness/log/consistency?first=${rc.tree_size}&second=${ck.tree_size}`);
  const r = L.checkHeads(hs, he, cons.path, cb, pin);
  say("the receipt's tree is a prefix of the cosigned tree", r.ok && hs.root_hash === rc.root_hash && he.root_hash === ck.root_hash, r.first + " -> " + r.second);
}

// Tamper.
const T = (name, step, r) => say("tamper " + name + " -> " + step, !r.ok && r.step === step, r.why || "");
T("ratio-changed-in-answer", "ANSWER", checkDerived(A[0], ANS[0].replace("1.06", "1.08"), VL, VP, "market-data", c));
T("prior-settle-changed-in-kept-body", "BODY", checkDerived(A[0], ANS[0], VL, VP.map(p => p.seq === 0 ? { ...p, body: { ...p.body, prior_settle: 82.9 } } : p), "market-data", c));
T("statement-hidden-from-log", "LOGGED", L.checkLogged(memory[sfp(A[0])], { ...proofs[sfp(A[0])], entries: proofs[sfp(A[0])].entries.slice(1) }, cb, pin));
T("witness-answer-drops-a-line", "LOGGED", L.checkLogged(memory[sfp(A[0])].slice(0, -1), proofs[sfp(A[0])], cb, pin));
T("cosignature-removed", "COSIGNED", L.checkCheckpoint(cp.split("\n").filter(l => !l.includes("ice-standin")).join("\n"), cb, { origin: COS.origin, logKey: WKEY, cosigners: COS.cosigners, quorum: 2 }));
const altered = C.encode(new C.Tag(18, [t.value[0], new Map(), new TextEncoder().encode(new TextDecoder().decode(t.value[2]).replace('"unrecorded":[{', '"unrecorded":[{"x":1,')), t.value[3]]));
T("registered-match-edited", "RECEIPT", L.checkReceipt(t.value[1].get(394)[0], altered, cb, pin));
const h1 = await get("/v1/witness/log/head?tree_size=36"), h2 = await get("/v1/witness/log/head?tree_size=" + ck.tree_size);
const cons2 = await get(`/v1/witness/log/consistency?first=36&second=${ck.tree_size}`);
T("history-rewritten-before-36", "SPLIT", L.checkHeads(h1, h2, cons2.path.map((h, i) => i === cons2.path.length - 1 ? "0".repeat(64) : h), cb, pin));
T("delivery-erased-from-gateway-log", "DELIVERIES", checkMatch(M, A, VL.slice(0, 3), c, opts));
if (vk) {
  const { sig: _s, accepted: _a, ...mb } = M;
  const signM = b => ({ ...b, sig: crypto.sign(null, Buffer.from(canon(b)), vk).toString("base64url") });
  T("outside-pull-hidden-from-match", "MATCH", checkMatch({ ...signM({ ...mb, unrecorded: [] }), accepted: M.accepted }, A, VL, c, opts));
} else console.log("skip outside-pull-hidden-from-match (needs the stand-in vendor key)");
console.log(`\n${ok} of ${all} checks passed.`);
process.exit(ok === all ? 0 : 1);
