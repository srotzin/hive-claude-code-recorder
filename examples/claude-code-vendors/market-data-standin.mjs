// A local stand-in for a licensed market-data MCP server. Values are made up for the demo.
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
const out = m => process.stdout.write(JSON.stringify(m) + "\n");
const tools = [
  { name: "get_eod", description: "End-of-day settlement for a futures dataset. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. futures.brent.eod" }, date: { type: "string" } }, required: ["dataset", "date"] } },
  { name: "get_records", description: "Rows from a licensed dataset. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. mortgage.loan-level" }, limit: { type: "integer" } }, required: ["dataset"] } },
];
rl.on("line", l => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "initialize") return out({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "market-data", version: "0.1.0-standin" } } });
  if (m.method === "tools/list") return out({ jsonrpc: "2.0", id: m.id, result: { tools } });
  if (m.method === "tools/call") {
    const a = m.params.arguments || {};
    const body = m.params.name === "get_eod"
      ? { dataset: a.dataset, date: a.date, settle: 84.12, currency: "USD", note: "stand-in value" }
      : { dataset: a.dataset, rows: Array.from({ length: Math.min(a.limit || 5, 5) }, (_, i) => ({ loan: "L" + (1000 + i), balance: 250000 + i * 1000 })), note: "stand-in rows" };
    return out({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify(body) }] } });
  }
  out({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown method" } });
});
