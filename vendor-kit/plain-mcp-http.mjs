// A stand-in for a vendor's own MCP server over Streamable HTTP, with no Hive code in it.
// The gateway (mcp-gateway.mjs) sits in front of it. Values are made up for the demo.
//   PORT (default 8811), MODE=json|sse (how it answers when the client accepts both)
import http from "node:http";
import crypto from "node:crypto";

const MODE = process.env.MODE || "json";
const tools = [
  { name: "get_eod", description: "End-of-day settlement and prior settlement for a futures dataset. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. futures.brent.eod or futures.wti.eod" }, date: { type: "string" } }, required: ["dataset"] } },
  { name: "get_records", description: "Rows from a licensed dataset. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. mortgage.loan-level" }, limit: { type: "integer" } }, required: ["dataset"] } },
];
const EOD = { "futures.brent.eod": { settle: 84.12, prior_settle: 81.9 }, "futures.wti.eod": { settle: 79.35, prior_settle: 78.6 } };
function call(name, a) {
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
