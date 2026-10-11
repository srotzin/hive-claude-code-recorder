// The zero-code gateway in front of a plain vendor MCP server (no Hive code), over Streamable HTTP,
// in both JSON and SSE response modes, against a witness with memory (HIVE_TEST_WITNESS, default local).
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { startGateway } from "../vendor-kit/mcp-gateway.mjs";
import { checkDeliveries, DELIVERY_ID } from "../plugins/hive-recorder/scripts/core.mjs";
import { c as vc } from "../plugins/hive-recorder/scripts/verify.mjs";

const W = process.env.HIVE_TEST_WITNESS || "http://localhost:8799";
let pass = 0, fail = 0;
const ok = (n, cond, extra = "") => { (cond ? pass++ : fail++); console.log((cond ? "PASS " : "FAIL ") + n + (extra ? "  " + extra : "")); };
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gw-"));
const keyPem = path.join(dir, "vendor.pem");
const { privateKey } = crypto.generateKeyPairSync("ed25519");
fs.writeFileSync(keyPem, privateKey.export({ type: "pkcs8", format: "pem" }));
const vpub = crypto.createPublicKey(privateKey).export({ format: "jwk" }).x;
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const procs = [];
const up = (port, mode) => new Promise(r => { const p = spawn("node", ["vendor-kit/plain-mcp-http.mjs"], { env: { ...process.env, PORT: String(port), MODE: mode } }); procs.push(p); p.stdout.once("data", r); });
await up(8821, "json"); await up(8822, "sse");
const base = { vendor: "market-data", key: keyPem, logs: dir, customers: { [sha("firm-token")]: "firm-a" }, dataset_arg: "dataset" };
const gws = [
  await startGateway({ ...base, port: 8831, upstream: "http://127.0.0.1:8821/mcp", witnesses: [W + "/v1/witness"] }),
  await startGateway({ ...base, port: 8832, upstream: "http://127.0.0.1:8822/mcp", witnesses: [W + "/v1/witness"] }),
  await startGateway({ ...base, port: 8833, upstream: "http://127.0.0.1:8821/mcp", witnesses: ["http://127.0.0.1:1/v1/witness"], logs: path.join(dir, "down"), timeout_ms: 800 }),
];
fs.mkdirSync(path.join(dir, "down"));
const rpc = async (port, body, token = "firm-token") => {
  const r = await fetch(`http://127.0.0.1:${port}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer " + token, "mcp-protocol-version": "2025-06-18" }, body: JSON.stringify(body) });
  return { status: r.status, type: r.headers.get("content-type"), session: r.headers.get("mcp-session-id"), text: await r.text() };
};
const sseMsgs = t => t.split(/\n\n/).filter(Boolean).map(ev => JSON.parse(ev.split("\n").filter(l => l.startsWith("data:")).map(l => l.slice(5).trim()).join("")));
const callBrent = { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "get_eod", arguments: { dataset: "futures.brent.eod" } } };

// Pass-through: initialize and tools/list come back as the vendor sent them.
const direct = await (await fetch("http://127.0.0.1:8821/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) })).text();
const via = await rpc(8831, { jsonrpc: "2.0", id: 2, method: "tools/list" });
ok("tools/list passes through byte for byte", via.text === direct);
const init = await rpc(8831, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
ok("initialize passes through with the vendor's session id header", init.status === 200 && !!init.session);

// JSON mode.
const j = await rpc(8831, callBrent);
const jm = JSON.parse(j.text), stamp = jm.result._meta["com.thehiveryiq/delivery"];
ok("JSON: the tools/call result carries the delivery under result._meta", /^dl-[a-z]{24}$/.test(stamp.delivery) && stamp.witnessed === 1, JSON.stringify(stamp));
ok("JSON: the vendor's own content is unchanged and the id is one more text block", jm.result.content[0].text.includes("84.12") && JSON.parse(jm.result.content[1].text).delivery === stamp.delivery);
ok("JSON: the recorder's delivery pattern finds the id in the result", (DELIVERY_ID.exec(JSON.stringify(jm.result)) || [])[1] === stamp.delivery);

// SSE mode: the progress event passes untouched, the response event is stamped.
const s = await rpc(8832, { ...callBrent, id: 8 });
const msgs = sseMsgs(s.text);
ok("SSE: the progress notification passes through untouched", msgs[0].method === "notifications/progress" && !msgs[0].result);
const sm = msgs.find(m => m.id === 8);
ok("SSE: the response event (sent in two pieces by the vendor) is stamped", s.type.startsWith("text/event-stream") && /^dl-/.test(sm.result._meta["com.thehiveryiq/delivery"].delivery));

// Concurrency: 6 calls at once take 6 different sequence numbers.
const many = await Promise.all([0, 1, 2, 3, 4, 5].map(i => rpc(8831, { jsonrpc: "2.0", id: 100 + i, method: "tools/call", params: { name: "get_records", arguments: { dataset: "mortgage.loan-level", limit: 3 } } })));
const seqs = many.map(m => JSON.parse(m.text).result._meta["com.thehiveryiq/delivery"].seq).sort((a, b) => a - b);
ok("6 calls at once take 6 different sequence numbers", new Set(seqs).size === 6, seqs.join(","));

// The log the gateway kept checks against the witness's memory.
const vlog = fs.readFileSync(path.join(dir, "market-data.firm-a.jsonl"), "utf8").trim().split("\n").map(l => JSON.parse(l));
const logFp = vlog[0].log;
const mem = (await (await fetch(`${W}/v1/witness/statements?recorder_key=${vpub}&session_fp=${logFp}`)).json()).statements;
const r = checkDeliveries(vlog, vc, { vendorPin: vpub, memory: mem, requireMemory: true });
ok("the gateway's delivery log checks: chain, vendor signature, every delivery witnessed", r.ok && vlog.length === 8, r.ok ? vlog.length + " deliveries" : r.step + " " + r.why);

// Refusals.
const u = await rpc(8831, { ...callBrent, id: 9 }, "someone-else");
ok("an unknown customer's tools/call is refused before it reaches the vendor", u.status === 401);
const err = await rpc(8831, { jsonrpc: "2.0", id: 10, method: "tools/call", params: { name: "no_such_tool", arguments: {} } });
ok("a vendor error passes through and is not logged as a delivery", JSON.parse(err.text).result?.isError === true && fs.readFileSync(path.join(dir, "market-data.firm-a.jsonl"), "utf8").trim().split("\n").length === 8, String(fs.readFileSync(path.join(dir, "market-data.firm-a.jsonl"), "utf8").trim().split("\n").length) + " lines");
const down = await rpc(8833, { ...callBrent, id: 11 });
const dm = JSON.parse(down.text);
ok("witness down, fail closed: the data is held back and nothing enters the log", dm.error && !down.text.includes("84.12") && !fs.existsSync(path.join(dir, "down", "market-data.firm-a.jsonl")), dm.error && dm.error.message);

for (const g of gws) g.close(); for (const p of procs) p.kill();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
