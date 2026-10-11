// Answer passport checks: the live passport verifies with the network switched off, and every refusal case
// is refused at the step that should catch it.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyPassport } from "../passport/verify-core.mjs";
import { nodeDeps, LIVE_PINS } from "../passport/verify.mjs";
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EX = path.join(ROOT, "examples/answer-passport");
let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { (cond ? pass++ : fail++); console.log((cond ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); };
globalThis.fetch = () => { throw new Error("no network during verification"); };
const base = JSON.parse(fs.readFileSync(path.join(EX, "passport.json"), "utf8"));
let r = await verifyPassport(base, LIVE_PINS, nodeDeps);
ok("the live passport verifies offline: approved, proven, delivered, bound, committed, in order, answered", r.ok && r.steps.length === 7 && r.figure === "146.2", r.ok ? r.figure + " " + r.unit : r.why);
for (const k of ["y", "b", "w", "ys", "bs", "ws"]) ok("the passport carries no private input (" + k + ")", !JSON.stringify(base.proof).includes('"' + k + '"'));
ok("the passport never contains a delivered yield, benchmark or weight", !/4\.912|3\.874|12000|"5287"|"1319"/.test(JSON.stringify(base)));
const { cases } = JSON.parse(fs.readFileSync(path.join(EX, "attacks.json"), "utf8"));
for (const c of cases) { r = await verifyPassport(c.passport, LIVE_PINS, nodeDeps); ok(`refused at ${c.expect}: ${c.title}`, !r.ok && r.step === c.expect, r.ok ? "accepted" : r.step + ": " + r.why); }
r = await verifyPassport(base, { ...LIVE_PINS, group_key: LIVE_PINS.firm_key }, nodeDeps);
ok("with the wrong shared key pinned, nothing verifies", !r.ok && r.step === "APPROVED");
r = await verifyPassport(base, { ...LIVE_PINS, log_key: LIVE_PINS.vendor_key }, nodeDeps);
ok("with the wrong log key pinned, nothing verifies", !r.ok && r.step === "APPROVED");
const cut = JSON.parse(JSON.stringify(base)); cut.inputs.witness_statements = cut.inputs.witness_statements.slice(0, 1);
r = await verifyPassport(cut, LIVE_PINS, nodeDeps);
ok("a passport that drops a witness statement is refused", !r.ok && r.step === "DELIVERED", r.why);
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
