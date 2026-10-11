// A local stand-in for a licensed reference-data MCP server, with a delivery log. Values are made up for the demo.
//   HIVE_DELIVERY_LOG (file), HIVE_VENDOR_KEY (Ed25519 PEM), HIVE_CUSTOMER, HIVE_WITNESS (url, optional)
import readline from "node:readline";
import { openDeliveryLog } from "./delivery-log.mjs";
const log = openDeliveryLog({ file: process.env.HIVE_DELIVERY_LOG, keyPem: process.env.HIVE_VENDOR_KEY, vendor: "ref-data", customer: process.env.HIVE_CUSTOMER || "firm-demo",
  log: "ref-data/" + (process.env.HIVE_CUSTOMER || "firm-demo"), witnesses: process.env.HIVE_WITNESS ? [process.env.HIVE_WITNESS] : [] });
const rl = readline.createInterface({ input: process.stdin });
const out = m => process.stdout.write(JSON.stringify(m) + "\n");
const tools = [
  { name: "get_issuer", description: "Issuer reference record. Stand-in data.", inputSchema: { type: "object", properties: { dataset: { type: "string", description: "e.g. issuers.reference" }, id: { type: "string" } }, required: ["dataset", "id"] } },
];
rl.on("line", async l => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "initialize") return out({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "ref-data", version: "0.2.0-standin" } } });
  if (m.method === "tools/list") return out({ jsonrpc: "2.0", id: m.id, result: { tools } });
  if (m.method === "tools/call") {
    const a = m.params.arguments || {};
    const body = { dataset: a.dataset, issuer: a.id, name: "Northwind Refining (stand-in)", rating: "A-", shares_outstanding: 41250000, note: "stand-in record" };
    const delivery = await log.deliver({ tool: m.params.name, datasets: [String(a.dataset)], body });
    return out({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ ...body, delivery }) }] } });
  }
  out({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown method" } });
});
