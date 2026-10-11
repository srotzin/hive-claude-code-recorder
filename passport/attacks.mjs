#!/usr/bin/env node
// Builds the refusal cases for an answer passport. Each is something a firm, an agent, a vendor or a
// middleman might try; each must be refused at the named step. Writes one JSON file with all of them.
//   node attacks.mjs --base passport.json --out attacks.json  (plus the same flags as prove.mjs)
import fs from "node:fs";
import crypto from "node:crypto";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
import { prove } from "./prove.mjs";

const opt = n => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : undefined; };
const base = JSON.parse(fs.readFileSync(opt("base"), "utf8"));
const clone = () => JSON.parse(JSON.stringify(base));
const o = { transcript: opt("transcript"), weights: opt("weights"), weightsStatement: opt("weights-statement"), approved: opt("approved"), vendorLog: opt("vendor-log"),
  log: opt("log") || "https://witness.thehiveryiq.com", vendorKey: "fzRLBYluTLJaa2DW8T11AaBbIH2OUE8hk8akjX9BNgI" };
const cases = [];
const add = (id, who, title, expect, passport) => cases.push({ id, who, title, expect, passport });

{ const p = clone(); p.answer.figure = "146.3"; p.answer.text = p.answer.text.replace("146.2", "146.3");
  add("figure", "the agent or whoever edits the answer", "The answer says 146.3 bp instead of 146.2", "ANSWER", p); }
{ const p = clone(); p.proof.public_signals[3] = "1463"; p.answer.figure = "146.3"; p.answer.text = p.answer.text.replace("146.2", "146.3");
  add("signal", "a middleman", "The proven result is changed to 1463 to match an edited answer", "PROOF", p); }
{ const p = clone(); const k = Object.keys(p.proof.proof).find(x => /^[A-Z]/.test(x) && Array.isArray(p.proof.proof[x])); p.proof.proof[k][0] = (BigInt(p.proof.proof[k][0]) + 1n).toString();
  add("proof", "a middleman", "One number inside the proof is changed", "PROOF", p); }
{ const p = await prove({ ...o, tweakYield: { index: 4, pct: 6.744 } });
  add("yields", "the firm", "A valid proof over a yield the vendor never delivered (DEMOBND05 at 6.744% instead of 6.344%)", "BOUND", p); }
{ const p = clone(); p.inputs.evaluations_seq = p.inputs.benchmarks_seq;
  add("swap", "the firm", "The benchmark delivery is passed off as the yields delivery", "DELIVERED", p); }
{ const p = clone(); const l = p.inputs.vendor_log[p.inputs.evaluations_seq]; l.commitment.value_commitment = p.proof.public_signals[1];
  add("vendorlog", "anyone holding the vendor log", "The vendor's signed delivery line is edited to point at other values", "DELIVERED", p); }
{ const p = await prove({ ...o, otherWeights: ["12000", "5000", "7500", "3000", "4500", "6000", "10000", "9000"] });
  p.answer.figure = (Number(p.proof.public_signals[3]) / 10).toFixed(1); p.answer.text = "Par-weighted spread: " + p.answer.figure + " bp";
  add("weights", "the firm", "A valid proof over different weights that were never committed in the log (gives " + p.answer.figure + " bp)", "WEIGHTS", p); }
{ const p = await prove({ ...o, weights: opt("late-weights"), weightsStatement: opt("late-weights-statement") });
  add("late", "the firm", "The same weights, committed again after the data arrived", "ORDER", p); }
{ const p = await prove({ ...o, circuit: "spread-equal-weight" });
  p.answer.figure = (Number(p.proof.public_signals[3]) / 10).toFixed(1); p.answer.text = "Par-weighted spread: " + p.answer.figure + " bp";
  add("formula", "the firm or the agent", "A valid proof of a different formula, the equal-weighted average (gives " + p.answer.figure + " bp)", "APPROVED", p); }
{ // the calculation approved by one key instead of the shared key
  const p = clone(), sk = crypto.createPrivateKey(fs.readFileSync(opt("one-key"))), pub = crypto.createPublicKey(sk).export({ format: "jwk" }).x, te = new TextEncoder();
  const t = C.decode(Buffer.from(p.calculation.signed_statement, "base64")), payload = t.value[2];
  const prot = C.encode(new Map([[1, C.ALG_EDDSA], [3, "application/json"], [4, te.encode(pub)], [15, new Map([[1, "firm-standin.thehiveryiq.com"], [2, "hive.approved-calculation/1"]])]]));
  const sig = new Uint8Array(crypto.sign(null, C.encode(["Signature1", prot, new Uint8Array(0), payload]), sk));
  p.calculation.signed_statement = Buffer.from(C.encode(new C.Tag(18, [prot, new Map(), payload, sig]))).toString("base64");
  add("onekey", "one party alone", "The calculation approved by the firm's key alone, without a second holder of the shared key", "APPROVED", p); }
fs.writeFileSync(opt("out"), JSON.stringify({ v: "hive.answer-passport-attacks/1", base_sha256: crypto.createHash("sha256").update(canon(base)).digest("hex"), cases }, null, 1) + "\n");
console.log(cases.map(c => c.id + " -> " + c.expect).join("\n"));
process.exit(0);
