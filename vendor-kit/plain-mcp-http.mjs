// A stand-in for a vendor's own MCP server over Streamable HTTP, with no Hive code in it.
// The gateway (mcp-gateway.mjs) sits in front of it. Values are made up for the demo.
//   PORT (default 8811), MODE=json|sse (how it answers when the client accepts both)
import http from "node:http";
import crypto from "node:crypto";

const MODE = process.env.MODE || "json";
const tools = [
  { name: "get_eod", description: "End-of-day settlement and prior settlement for a futures dataset. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. futures.brent.eod or futures.wti.eod" }, date: { type: "string" } }, required: ["dataset"] } },
  { name: "get_records", description: "Rows from a licensed dataset. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. mortgage.loan-level" }, limit: { type: "integer" } }, required: ["dataset"] } },
  { name: "get_bond_evaluations", description: "Evaluated yield to maturity for corporate bonds, end of day. Stand-in data for fictional bonds DEMOBND01 to DEMOBND08.", inputSchema: { type: "object", properties: { dataset: { type: "string", enum: ["bonds.evaluated-pricing"] }, cusips: { type: "array", items: { type: "string" }, description: "bond identifiers, returned in the order given" }, date: { type: "string" } }, required: ["dataset", "cusips"] } },
  { name: "get_benchmark_yields", description: "Maturity-matched Treasury benchmark yield for each bond, end of day. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", enum: ["bonds.benchmark-yields"] }, cusips: { type: "array", items: { type: "string" }, description: "bond identifiers, returned in the order given" }, date: { type: "string" } }, required: ["dataset", "cusips"] } },
];
// Fictional bonds. Yields in percent to three decimals.
const BONDS = {
  DEMOBND01: { issuer: "Demo Utilities", coupon: 4.25, maturity: "2029-06-15", yield_pct: 4.912, benchmark: "UST 3Y", benchmark_yield_pct: 3.874 },
  DEMOBND02: { issuer: "Demo Rail", coupon: 5.10, maturity: "2031-03-01", yield_pct: 5.287, benchmark: "UST 5Y", benchmark_yield_pct: 3.968 },
  DEMOBND03: { issuer: "Demo Telecom", coupon: 5.75, maturity: "2033-09-15", yield_pct: 5.731, benchmark: "UST 7Y", benchmark_yield_pct: 4.102 },
  DEMOBND04: { issuer: "Demo Health", coupon: 4.60, maturity: "2030-01-15", yield_pct: 4.806, benchmark: "UST 3Y", benchmark_yield_pct: 3.874 },
  DEMOBND05: { issuer: "Demo Energy", coupon: 6.20, maturity: "2035-11-01", yield_pct: 6.344, benchmark: "UST 10Y", benchmark_yield_pct: 4.236 },
  DEMOBND06: { issuer: "Demo Retail", coupon: 5.40, maturity: "2032-05-15", yield_pct: 5.958, benchmark: "UST 7Y", benchmark_yield_pct: 4.102 },
  DEMOBND07: { issuer: "Demo Bank", coupon: 4.95, maturity: "2031-08-01", yield_pct: 5.163, benchmark: "UST 5Y", benchmark_yield_pct: 3.968 },
  DEMOBND08: { issuer: "Demo Insurance", coupon: 5.05, maturity: "2034-02-15", yield_pct: 5.402, benchmark: "UST 10Y", benchmark_yield_pct: 4.236 },
};
const EOD = { "futures.brent.eod": { settle: 84.12, prior_settle: 81.9 }, "futures.wti.eod": { settle: 79.35, prior_settle: 78.6 } };
function call(name, a) {
  if (name === "get_bond_evaluations" || name === "get_benchmark_yields") {
    const want = name === "get_bond_evaluations" ? "bonds.evaluated-pricing" : "bonds.benchmark-yields";
    if (a.dataset !== want) return { error: "dataset must be " + want };
    const ids = (Array.isArray(a.cusips) ? a.cusips : []).map(String);
    const missing = ids.filter(c => !BONDS[c]); if (missing.length) return { error: "unknown bonds: " + missing.join(", ") };
    const rows = ids.map(c => name === "get_bond_evaluations" ? { cusip: c, issuer: BONDS[c].issuer, coupon: BONDS[c].coupon, maturity: BONDS[c].maturity, yield_pct: BONDS[c].yield_pct }
      : { cusip: c, maturity: BONDS[c].maturity, benchmark: BONDS[c].benchmark, benchmark_yield_pct: BONDS[c].benchmark_yield_pct });
    return { dataset: name === "get_bond_evaluations" ? "bonds.evaluated-pricing" : "bonds.benchmark-yields", date: a.date || "2026-10-09", rows, note: "stand-in values for fictional bonds" };
  }
  if (name === "get_eod") { const v = EOD[a.dataset] || { settle: 70.5, prior_settle: 70.1 }; return { dataset: a.dataset, date: a.date || "2026-10-09", ...v, currency: "USD", note: "stand-in value" }; }
  return { dataset: a.dataset, rows: Array.from({ length: Math.min(a.limit || 5, 5) }, (_, i) => ({ loan: "L" + (1000 + i), balance: 250000 + i * 1000 })), note: "stand-in rows" };
}
http.createServer((req, res) => {
  if (req.method !== "POST" || !req.url.startsWith("/mcp")) { res.writeHead(405, { allow: "POST" }); return res.end(); }
  let raw = ""; req.on("data", c => raw += c);
  req.on("end", () => {
    let m; try { m = JSON.parse(raw); } catch { res.writeHead(400); return res.end(); }
    if (m.id === undefined) { res.writeHead(202); return res.end(); }
    let reply;
    if (m.method === "initialize") reply = { jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "market-data", version: "0.3.0" } } };
    else if (m.method === "tools/list") reply = { jsonrpc: "2.0", id: m.id, result: { tools } };
    else if (m.method === "tools/call" && !tools.some(t => t.name === m.params?.name)) reply = { jsonrpc: "2.0", id: m.id, result: { isError: true, content: [{ type: "text", text: "unknown tool" }] } };
    else if (m.method === "tools/call") reply = { jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify(call(m.params.name, m.params.arguments || {})) }] } };
    else if (m.method === "ping") reply = { jsonrpc: "2.0", id: m.id, result: {} };
    else reply = { jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown method" } };
    const extra = m.method === "initialize" ? { "mcp-session-id": crypto.randomUUID() } : {};
    const sse = MODE === "sse" && /text\/event-stream/.test(req.headers.accept || "");
    if (!sse) { res.writeHead(200, { "content-type": "application/json", ...extra }); return res.end(JSON.stringify(reply)); }
    // SSE: a progress notification first (must pass through untouched), then the response, in two writes.
    res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", ...extra });
    if (m.method === "tools/call") res.write(`event: message\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/progress", params: { progressToken: "p" + m.id, progress: 1, total: 2 } })}\n\n`);
    const s = `event: message\nid: ${crypto.randomUUID()}\ndata: ${JSON.stringify(reply)}\n\n`, half = Math.floor(s.length / 2);
    res.write(s.slice(0, half)); setTimeout(() => { res.write(s.slice(half)); res.end(); }, 20);
  });
}).listen(Number(process.env.PORT || 8811), () => console.log("plain vendor MCP on", process.env.PORT || 8811, "mode", MODE));
