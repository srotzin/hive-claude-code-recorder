// A local stand-in for a second data vendor's MCP server: issuer reference data. Values are made up for the demo.
import readline from "node:readline";
const rl = readline.createInterface({ input: process.stdin });
const out = m => process.stdout.write(JSON.stringify(m) + "\n");
const tools = [
  { name: "get_issuer", description: "Reference record for an issuer. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. issuers.reference" }, id: { type: "string" } }, required: ["dataset", "id"] } },
];
rl.on("line", l => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "initialize") return out({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "ref-data", version: "0.1.0-standin" } } });
  if (m.method === "tools/list") return out({ jsonrpc: "2.0", id: m.id, result: { tools } });
  if (m.method === "tools/call") {
    const a = m.params.arguments || {};
    const body = { dataset: a.dataset, issuer: a.id, name: "Northwind Refining (stand-in)", rating: "A-", shares_outstanding: 41250000, note: "stand-in record" };
    return out({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify(body) }] } });
  }
  out({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown method" } });
});
