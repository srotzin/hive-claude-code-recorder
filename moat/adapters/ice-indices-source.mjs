// A thin MCP adapter the firm runs in front of ICE Data Indices' published index data, as distributed by FRED
// (St. Louis Fed) under ICE's licence. Each call fetches the source live and keeps a signed delivery line whose
// fingerprint is the SHA-256 of the exact bytes the source returned, so anyone can re-fetch and compare.
//   HIVE_DELIVERY_LOG, HIVE_VENDOR_KEY, HIVE_CUSTOMER, HIVE_WITNESS
import readline from "node:readline";
import crypto from "node:crypto";
import { openDeliveryLog } from "/opt/hive-mcp/delivery-log.mjs";
const log = openDeliveryLog({ file: process.env.HIVE_DELIVERY_LOG, keyPem: process.env.HIVE_VENDOR_KEY, vendor: "ice-indices", customer: process.env.HIVE_CUSTOMER || "firm-demo",
  log: "ice-indices/" + (process.env.HIVE_CUSTOMER || "firm-demo"), witnesses: process.env.HIVE_WITNESS ? [process.env.HIVE_WITNESS] : [] });
const rl = readline.createInterface({ input: process.stdin });
const out = m => process.stdout.write(JSON.stringify(m) + "\n");
const tools = [{ name: "get_index_value", description: "Daily close of an ICE BofA index series (ICE Data Indices, LLC), from its published distribution on FRED.", inputSchema: { type: "object", properties: { series: { type: "string", description: "FRED series id, e.g. BAMLH0A0HYM2EY (ICE BofA US High Yield Index Effective Yield, percent)" }, date: { type: "string", description: "YYYY-MM-DD" } }, required: ["series", "date"] } }];
rl.on("line", async l => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "initialize") return out({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "ice-indices", version: "0.1.0" } } });
  if (m.method === "tools/list") return out({ jsonrpc: "2.0", id: m.id, result: { tools } });
  if (m.method === "tools/call") {
    const a = m.params.arguments || {};
    const series = String(a.series || "").replace(/[^A-Z0-9]/g, ""), date = String(a.date || "").slice(0, 10);
    const url = `https://fred.stlouisfed.org/graph/fredgraph.csv?id=${series}&cosd=${date}&coed=${date}`;
    const r = await fetch(url); const raw = await r.text();
    const row = raw.trim().split("\n")[1]; const value = row ? row.split(",")[1] : null;
    const body = { series, date, value, units: "percent", source: "ICE Data Indices, LLC, as published on FRED", source_url: url, source_sha256: crypto.createHash("sha256").update(raw).digest("hex") };
    const delivery = await log.deliver({ tool: m.params.name, datasets: ["ice-bofa." + series], body });
    return out({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ ...body, delivery }) }] } });
  }
  out({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown method" } });
});
