// Real ICE index data (ICE BofA via FRED) and U.S. Treasury yields in one figure, examples/claude-code-real-source.
// ICE's side of the check needs nothing from the firm or Hive: it re-fetches the public source, rebuilds the delivered
// body, matches the signed delivery line, and opens its input in the registered split. Needs the network.
import fs from "node:fs";
import crypto from "node:crypto";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
import { c } from "../plugins/hive-recorder/scripts/verify.mjs";
import * as L from "../plugins/hive-recorder/scripts/log-check.mjs";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";
import { checkMyInput, checkArithmetic } from "../moat/split.mjs";
const E = new URL("../examples/claude-code-real-source/", import.meta.url).pathname;
const jl = f => fs.readFileSync(E + f, "utf8").split("\n").filter(Boolean).map(JSON.parse), js = f => JSON.parse(fs.readFileSync(E + f, "utf8"));
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const WKEY = "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE";
const cb = { sha256: u => new Uint8Array(crypto.createHash("sha256").update(u).digest()), verifyBytes: (pub, msg, sig) => { try { return crypto.verify(null, Buffer.from(msg), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub }, format: "jwk" }), Buffer.from(sig)); } catch { return false; } } };
let pass = 0, all = 0; const ok = (n, b, d = "") => { all++; if (b) pass++; console.log((b ? "ok   " : "FAIL ") + n + (d ? "  " + d : "")); };
const st = js("split.json"), I = { copy: jl("copies/session.ice-indices.jsonl"), vlog: jl("vendor/ice-indices.deliveries.jsonl") };
const T = { copy: jl("copies/session.us-treasury.jsonl"), vlog: jl("vendor/us-treasury.deliveries.jsonl"), kept: jl("vendor/us-treasury.kept-bodies.jsonl"), op: js("firm/opening.us-treasury.json") };

// The body the ICE adapter delivered, rebuilt from the public source alone.
export function iceBody(series, date, raw) {
  const row = raw.trim().split("\n")[1];
  return { series, date, value: row ? row.split(",")[1] : null, units: "percent", source: "ICE Data Indices, LLC, as published on FRED",
    source_url: `https://fred.stlouisfed.org/graph/fredgraph.csv?id=${series}&cosd=${date}&coed=${date}`, source_sha256: sha(raw) };
}
const d0 = I.vlog[0];
const raw = await (await fetch(`https://fred.stlouisfed.org/graph/fredgraph.csv?id=BAMLH0A0HYM2EY&cosd=2026-10-08&coed=2026-10-08`)).text();
const body = iceBody("BAMLH0A0HYM2EY", "2026-10-08", raw);
ok("re-fetched from FRED, the rebuilt body is the one ICE's adapter signed", sha(canon(body)) === d0.body_sha256, "delivery " + d0.seq + ", " + d0.datasets.join());
const iceOp = { split_sha256: c.sha256hex(canon(st)), input: st.inputs.findIndex(x => x.delivery_fp === d0.delivery_fp), value: body.value };
let r = checkMyInput(st, iceOp, I.copy, I.vlog, [{ delivery_fp: d0.delivery_fp, body }], c);
ok("ICE's side opens its own input with the value it fetched itself", r.ok, r.ok ? `${r.my_input} in ${st.figure} = ${st.op}` : r.step + ", " + r.why);
r = checkMyInput(st, T.op, T.copy, T.vlog, T.kept, c);
ok("the Treasury side opens its own input", r.ok, r.ok ? `${r.my_value} is ${r.my_input}` : r.step + ", " + r.why);
ok("an auditor with both gets 289 bp", checkArithmetic(st, [iceOp, T.op], c).ok);
const t = C.decode(fs.readFileSync(E + "split.transparent.cose")), emptied = C.encode(new C.Tag(18, [t.value[0], new Map(), t.value[2], t.value[3]]));
const rc = L.checkReceipt(t.value[1].get(394)[0], emptied, cb, { witnessPin: WKEY });
ok("the split is on the public log", rc.ok && canon(JSON.parse(new TextDecoder().decode(t.value[2]))) === canon(st), rc.ok ? `leaf ${rc.leaf_index}` : rc.why);
ok("nothing in this folder reproduces the ICE value", !fs.readdirSync(E, { recursive: true }).some(f => { try { return fs.readFileSync(E + f, "utf8").includes(body.value); } catch { return false; } }));
const wrong = String((Number(body.value) + 0.01).toFixed(2));
r = checkMyInput(st, { ...iceOp, value: wrong }, I.copy, I.vlog, [{ delivery_fp: d0.delivery_fp, body: { ...body, value: wrong } }], c);
ok("refused: ICE's input opened to a value FRED did not publish", !r.ok && r.step === "VALUE", r.step);
ok("refused: a rebuilt body with a different source byte", sha(canon(iceBody("BAMLH0A0HYM2EY", "2026-10-08", raw + " "))) !== d0.body_sha256);
console.log(`\n${pass} of ${all} checks passed.`); process.exit(pass === all ? 0 : 1);
