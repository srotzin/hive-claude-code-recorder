#!/usr/bin/env node
// Builds an answer passport from a finished Claude Code session. Run by the firm, on its own machine:
// it needs the session transcript (for the delivered values and salts and the agent's answer), the firm's
// private weights, the vendor's delivery log (fingerprints only, as in the delivery match) and the public log.
// Nothing private goes into the passport: the proof reveals the result and three commitments.
//
//   node prove.mjs --transcript <session.jsonl> --weights weights.private.json --weights-statement weights
//                  --approved approved-calculation (prefix: .json, .signed-statement.cose, .receipt.cose)
//                  --vendor-log market-data.firm-demo-5.jsonl --log https://witness.thehiveryiq.com --out passport.json
//   optional: --circuit spread (build/<circuit>_js, build/<circuit>.zkey, keys/<circuit>.vkey.json)
//   prove() also takes { tweakYield: { index, pct }, otherWeights: [par...], figureOverride } to build the refusal cases in attacks.mjs.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
import { idToField, toUnits, textToSalt, commitVector, newSalt } from "../vendor-kit/lib/commit.mjs";
import { PASSPORT_FORMAT } from "./verify-core.mjs";

const here = path.dirname(new URL(import.meta.url).pathname);
const opt = n => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : undefined; };
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const b64 = f => fs.readFileSync(f).toString("base64");
const jl = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);

// The delivered values, salts and delivery ids, exactly as the agent received them.
export function fromTranscript(file) {
  const uses = new Map(), results = [];
  let answer = null;
  for (const d of jl(file)) {
    const c = d.message && d.message.content;
    if (d.type === "assistant" && Array.isArray(c)) for (const x of c) { if (x.type === "tool_use") uses.set(x.id, x); if (x.type === "text") answer = x.text; }
    if (Array.isArray(c)) for (const x of c) if (x.type === "tool_result") results.push(x);
  }
  const got = {};
  for (const r of results) {
    const u = uses.get(r.tool_use_id); if (!u) continue;
    const tool = u.name.split("__").pop();
    if (!/get_bond_evaluations|get_benchmark_yields/.test(tool)) continue;
    const texts = (Array.isArray(r.content) ? r.content : []).filter(x => x.type === "text").map(x => JSON.parse(x.text));
    const body = texts.find(t => t.rows), stamp = texts.find(t => t.delivery && t.commitment_salt);
    if (!body || !stamp) throw new Error(tool + ": the result carries no delivery id and salt; was the vendor's gateway set to commit?");
    got[tool] = { body, delivery: stamp.delivery, salt: textToSalt(stamp.commitment_salt), input: u.input };
  }
  return { evaluations: got.get_bond_evaluations, benchmarks: got.get_benchmark_yields, answer };
}

export async function prove(o) {
  const t = fromTranscript(o.transcript);
  if (!t.evaluations || !t.benchmarks) throw new Error("the session did not fetch both evaluations and benchmarks");
  const w = JSON.parse(fs.readFileSync(o.weights, "utf8"));
  const approved = JSON.parse(fs.readFileSync(o.approved + ".json", "utf8"));
  const spec = approved.inputs || approved.statement.inputs;
  const ids = t.evaluations.body.rows.map(r => r[spec.Cy.id]);
  if (canon(ids) !== canon(t.benchmarks.body.rows.map(r => r[spec.Cb.id]))) throw new Error("the two deliveries list the bonds in different orders");
  if (canon(ids) !== canon(w.ids)) throw new Error("the deliveries list the bonds in a different order from the committed weights");
  const y = t.evaluations.body.rows.map(r => toUnits(r[spec.Cy.value], spec.Cy.scale));
  const b = t.benchmarks.body.rows.map(r => toUnits(r[spec.Cb.value], spec.Cb.scale));
  if (o.tweakYield) y[o.tweakYield.index] = toUnits(o.tweakYield.pct, spec.Cy.scale);
  const par = (o.otherWeights || w.par_thousands).map(BigInt);
  const wt = (o.circuit === "spread-equal-weight") ? par.map(() => 1n) : par; // the unapproved formula, for the refusal case
  const S = y.reduce((a, yi, i) => a + wt[i] * (yi - b[i]), 0n), W = wt.reduce((a, x) => a + x, 0n);
  const R = (2n * S + W) / (2n * W);
  const figure = o.figureOverride || (Number(R) / 10).toFixed(1);
  const vlog = jl(o.vendorLog);
  const seqOf = id => { const l = vlog.find(x => x.delivery_fp === sha(id)); if (!l) throw new Error("delivery " + id + " is not in the vendor's log"); return l.seq; };
  const ev = vlog[seqOf(t.evaluations.delivery)], bm = vlog[seqOf(t.benchmarks.delivery)];
  const input = {
    id: ids.map(s => idToField(s).toString()),
    y: y.map(String), ys: t.evaluations.salt.toString(),
    b: b.map(String), bs: t.benchmarks.salt.toString(),
    w: par.map(String), ws: textToSalt(w.salt).toString(),
    Cy: ev.commitment.value_commitment, Cb: bm.commitment.value_commitment,
    Cw: JSON.parse(fs.readFileSync(o.weightsStatement + ".json", "utf8")).commitment, R: R.toString(),
  };
  // Refusal cases: a valid proof over yields the vendor never delivered, or weights the firm never logged.
  if (o.tweakYield) { const s = newSalt(); input.ys = s.toString(); input.Cy = commitVector(ids, y, s); }
  if (o.otherWeights) { const s = newSalt(); input.ws = s.toString(); input.Cw = commitVector(ids, par, s); }
  const circuit = o.circuit || "spread";
  const { proof, publicSignals } = await snarkjs.plonk.fullProve(input, path.join(here, "build", circuit + "_js", circuit + ".wasm"), path.join(here, "build", circuit + ".zkey"));
  const vkey = JSON.parse(fs.readFileSync(path.join(here, "keys", circuit + ".vkey.json"), "utf8"));
  const lf = ev.log, vk = o.vendorKey;
  const witness_statements = (await (await fetch(`${o.log}/v1/witness/statements?recorder_key=${vk}&session_fp=${lf}`)).json()).statements;
  const witness_proofs = await (await fetch(`${o.log}/v1/witness/log/proofs?recorder_key=${vk}&session_fp=${lf}`)).json();
  return {
    v: PASSPORT_FORMAT,
    answer: { text: t.answer.split("\n").filter(l => /Par-weighted spread/.test(l)).pop() || t.answer, figure, unit: "bp", agent: "Claude Code", session_fp: sha(path.basename(o.transcript, ".jsonl")) },
    calculation: { signed_statement: b64(o.approved + ".signed-statement.cose"), receipt: b64(o.approved + ".receipt.cose"), verification_key: vkey },
    inputs: {
      vendor_log: vlog, evaluations_seq: ev.seq, benchmarks_seq: bm.seq, witness_statements, witness_proofs,
      weights: { signed_statement: b64(o.weightsStatement + ".signed-statement.cose"), receipt: b64(o.weightsStatement + ".receipt.cose") },
    },
    proof: { system: "PLONK", curve: "bn128", public_signals: publicSignals, proof },
    made_at: new Date().toISOString(),
  };
}

if (import.meta.url === "file://" + process.argv[1]) {
  const p = await prove({ transcript: opt("transcript"), weights: opt("weights"), weightsStatement: opt("weights-statement"), approved: opt("approved"), vendorLog: opt("vendor-log"),
    log: opt("log") || "https://witness.thehiveryiq.com", vendorKey: opt("vendor-key") || "fzRLBYluTLJaa2DW8T11AaBbIH2OUE8hk8akjX9BNgI", circuit: opt("circuit"), figureOverride: opt("figure-override") });
  fs.writeFileSync(opt("out"), JSON.stringify(p, null, 1) + "\n");
  console.log(JSON.stringify({ figure: p.answer.figure, public_signals: p.proof.public_signals, proof_bytes: JSON.stringify(p.proof.proof).length }));
  process.exit(0);
}
