// Precision rules for figures derived across deliveries, on the real gateway example with altered answers.


import fs from "node:fs";
import { checkDerived } from "../plugins/hive-recorder/scripts/core.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";
const E = new URL("../examples/claude-code-gateway/", import.meta.url).pathname;
const rl = f => fs.readFileSync(E + f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
const A1 = rl("copies/session-1.market-data.jsonl"), VL = rl("vendor/market-data.deliveries.jsonl"), VP = rl("vendor/market-data.delivered-bodies.jsonl");
const ans = fs.readFileSync(E + "answer-1.txt", "utf8");
let pass = 0, all = 0; const ok = (n, b, d = "") => { all++; if (b) pass++; console.log((b ? "ok   " : "FAIL ") + n + (d ? "  " + d : "")); };
const r = checkDerived(A1, ans, VL, VP, "market-data", c);
const by = f => r.derived.filter(d => d.figure === f).map(d => d.op);
ok("4.77 is only the Brent minus WTI difference", by("4.77").join() === "difference");
ok("1.06 is only the Brent to WTI ratio", by("1.06").join() === "ratio");
ok("2.71 is only Brent's change from its prior settle", by("2.71").join() === "percent change");
ok("figures the delivery states outright are direct, not derived", ["84.12", "81.9", "79.35", "78.6"].every(f => r.direct.some(d => d.figure === f) && !by(f).length));
ok("the WTI change (0.95, 2 significant digits) is too short to trace", !r.derived.some(d => d.figure === "0.95"));
ok("each derived figure names both deliveries it came from", r.derived.filter(d => d.op === "difference" || d.op === "ratio").every(d => d.a.delivery_seq === 0 && d.b.delivery_seq === 1));
console.log(`\n${pass} of ${all} checks passed.`); process.exit(pass === all ? 0 : 1);
