// Builds the derived-figure split for examples/claude-code-cross-vendor from the firm's own records.
//   node moat/build-split.mjs <transcript tool results .json> <firm issuer key .pem> [--register]
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { canon, numbersIn, discloseFor } from "../plugins/hive-recorder/scripts/core.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";
import { findSplits, splitStatement } from "./split.mjs";
const E = new URL("../examples/claude-code-cross-vendor/", import.meta.url).pathname;
const jl = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
const lines = jl(E + "firm/session.jsonl"), answer = fs.readFileSync(E + "answer.txt", "utf8");
const results = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
// The numbers the agent received at each recorded step: the firm's own transcript, keyed by the step's tool use id.
const received = {};
for (const l of lines) if (l.event === "PostToolUse" && l.tool && results[l.tool.use_id]) received[l.seq] = numbersIn(results[l.tool.use_id]);
const found = findSplits(lines, answer, received, c);
if (found.length !== 1) { console.error("expected one cross-vendor figure, found " + found.length, found.map(f => f.figure + " " + f.op)); process.exit(2); }
const { statement, split_sha256, openings } = splitStatement(lines, answer, found[0], c);
fs.writeFileSync(E + "split.json", JSON.stringify(statement, null, 1) + "\n");
for (const o of openings) fs.writeFileSync(E + `firm/opening.${o.vendor}.json`, JSON.stringify(o.opening, null, 1) + "\n");
for (const v of [...new Set(openings.map(o => o.vendor))]) fs.writeFileSync(E + `copies/session.${v}.jsonl`, discloseFor(lines, v, c.sha256hex).map(l => JSON.stringify(l)).join("\n") + "\n");
console.log(JSON.stringify({ figure: statement.figure, op: statement.op, split_sha256, inputs: statement.inputs.length }));
if (process.argv.includes("--register")) {
  const out = execFileSync("node", [new URL("../vendor-kit/scitt-register.mjs", import.meta.url).pathname, "--log", "https://witness.thehiveryiq.com", "--key", process.argv[3],
    "--iss", "firm-standin.thehiveryiq.com", "--sub", "hive.derived-split/1", "--in", E + "split.json", "--out", E + "split"]).toString();
  console.log(out.trim());
}
