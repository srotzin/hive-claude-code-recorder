// Usage declaration: the vendor's fee categories over the signed match. Each holder signs only the declaration it computes
// from its own records and its own copy of the category map. Run against the stand-in holders' data.
import fs from "node:fs";
import { viewFor, inventoryOf } from "../shared-key/views.mjs";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
const P = process.env.HIVE_PARTIES || "/home/user/hive-parties", L = new URL("../shared-key/live/", import.meta.url).pathname;
const cfgOf = r => JSON.parse(fs.readFileSync(`${P}/${r}/party.json`, "utf8")), relOf = r => f => `${P}/${r}/${f}`;
const want = JSON.parse(fs.readFileSync(L + "usage-declaration.json", "utf8"));
let pass = 0, all = 0; const ok = (n, b, d = "") => { all++; if (b) pass++; console.log((b ? "ok   " : "FAIL ") + n + (d ? "  " + d : "")); };
const signs = async (cfg, rel, stmt) => { try { return canon(await viewFor(cfg, rel, stmt, {})) === canon(stmt); } catch (e) { return e.refused ? false : (() => { throw e; })(); } };
const vcfg = cfgOf("vendor"), vrel = relOf("vendor");
const bent = f => { const s = JSON.parse(JSON.stringify(want)); f(s.declaration); return s; };
ok("the vendor computes the registered declaration byte for byte", await signs(vcfg, vrel, want));
ok("the declaration carries the pull made around the agent as its own line", want.declaration.lines.some(l => l.use === "outside_agent_record" && l.delivery_seqs.join() === "3"));
ok("no line carries a rate or an amount", want.declaration.lines.every(l => l.amount === null && l.rate === "per the vendor's fee schedule"));
ok("refused: the outside pull folded into agent use", !(await signs(vcfg, vrel, bent(d => { const o = d.lines.find(l => l.use === "outside_agent_record"); d.lines = d.lines.filter(l => l !== o); const a = d.lines.find(l => l.category === o.category && l.use === "agent_use"); a.deliveries++; a.delivery_seqs.push(3); d.totals.agent_use++; d.totals.outside_agent_record--; }))));
ok("refused: the outside pull dropped", !(await signs(vcfg, vrel, bent(d => { d.lines = d.lines.filter(l => l.use !== "outside_agent_record"); d.totals.outside_agent_record = 0; }))));
ok("refused: Brent moved into a different fee category", !(await signs(vcfg, vrel, bent(d => { d.lines[0].category = "Loan-level mortgage data"; }))));
ok("refused: an amount written into a line", !(await signs(vcfg, vrel, bent(d => { d.lines[0].amount = "0.00"; }))));
ok("refused: a delivery count changed", !(await signs(vcfg, vrel, bent(d => { d.lines[2].deliveries = 0; }))));
ok("refused: the category map fingerprint swapped", !(await signs(vcfg, vrel, bent(d => { d.categories_sha256 = "0".repeat(64); }))));
// A holder whose own map differs (the firm never agreed to a recategorisation) does not sign.
const tmp = fs.mkdtempSync("/tmp/decl-"); const alt = JSON.parse(fs.readFileSync(vrel(vcfg.data.fee_categories), "utf8")); alt.datasets["futures.brent.eod"] = "Real-time futures data";
fs.writeFileSync(tmp + "/alt.json", JSON.stringify(alt));
ok("refused: a holder whose own category map differs", !(await signs({ ...vcfg, data: { ...vcfg.data, fee_categories: tmp + "/alt.json" } }, f => f.startsWith("/") ? f : vrel(f), want)));
ok("refused: a holder with no category map", !(await signs({ ...vcfg, data: { ...vcfg.data, fee_categories: undefined } }, vrel, want)));
const plain = { ...want }; delete plain.declaration;
ok("a statement with no declaration is still the plain usage inventory", await signs(vcfg, vrel, plain) && canon(plain) === canon(inventoryOf(JSON.parse(fs.readFileSync(vrel(vcfg.data.match))), fs.readFileSync(vrel(vcfg.data.vendor_log), "utf8").split("\n").filter(Boolean).map(JSON.parse))));
console.log(`\n${pass} of ${all} checks passed.`); process.exit(pass === all ? 0 : 1);
