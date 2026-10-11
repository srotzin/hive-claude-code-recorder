#!/usr/bin/env node
// Writes the approved-calculation statement for a circuit: what it computes, where each input comes from,
// and the hashes of the circuit source and verification key. Each holder of the shared key keeps its own
// reviewed copy of the circuit and key and signs only if its own hashes match (shared-key/views.mjs).
//   node approve.mjs --circuit circuits/spread.circom --vkey keys/spread.vkey.json --out approved-calculation.json
import fs from "node:fs";
import crypto from "node:crypto";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
const opt = n => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : undefined; };
const sha = b => crypto.createHash("sha256").update(b).digest("hex");
export function approvedStatement(circuitBytes, vkey) {
  return {
    kind: "hive.approved-calculation/1",
    name: "Par-weighted average spread to benchmark",
    formula: "R = round half up of sum(w_i * (y_i - b_i)) / sum(w_i), with y and b in thousandths of a percent (tenths of a basis point) and w the par held",
    n: 8,
    output: { signal: 3, unit: "bp", scale: 10, decimals: 1 },
    public_signals: ["Cy", "Cb", "Cw", "R"],
    commitment_scheme: "hive.poseidon-commit/1",
    inputs: {
      Cy: { from: "vendor delivery", vendor: "market-data", tool: "get_bond_evaluations", dataset: "bonds.evaluated-pricing", rows: "rows", id: "cusip", value: "yield_pct", scale: 1000 },
      Cb: { from: "vendor delivery", vendor: "market-data", tool: "get_benchmark_yields", dataset: "bonds.benchmark-yields", rows: "rows", id: "cusip", value: "benchmark_yield_pct", scale: 1000 },
      Cw: { from: "firm commitment", kind: "hive.portfolio-commitment/1", value: "par_thousands", logged: "before the first delivery used" },
    },
    proof_system: "PLONK over BN254 (snarkjs 0.7.5); circuit compiled with circom 2.2.2 and circomlib 2.0.5",
    setup: { file: "ppot_0080_14.ptau", from: "Perpetual Powers of Tau, Privacy and Scaling Explorations", url: "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_14.ptau", sha256: "3ca1149e9349b22b0ee0649399cfb787677129b7b1189d1899fc0d615d9583db" },
    circuit_sha256: sha(circuitBytes),
    verification_key_sha256: sha(canon(vkey)),
  };
}
if (import.meta.url === "file://" + process.argv[1]) {
  const st = approvedStatement(fs.readFileSync(opt("circuit")), JSON.parse(fs.readFileSync(opt("vkey"), "utf8")));
  fs.writeFileSync(opt("out"), JSON.stringify({ statement: st, files: { circuit: opt("circuit"), verification_key: opt("vkey") } }, null, 1) + "\n");
  console.log(JSON.stringify({ circuit_sha256: st.circuit_sha256, verification_key_sha256: st.verification_key_sha256 }));
}
