// A thin MCP adapter in front of the U.S. Treasury's published daily par yield curve. Same delivery log as the ICE adapter.
import readline from "node:readline";
import crypto from "node:crypto";
import { openDeliveryLog } from "/opt/hive-mcp/delivery-log.mjs";
const log = openDeliveryLog({ file: process.env.HIVE_DELIVERY_LOG, keyPem: process.env.HIVE_VENDOR_KEY, vendor: "us-treasury", customer: process.env.HIVE_CUSTOMER || "firm-demo",
  log: "us-treasury/" + (process.env.HIVE_CUSTOMER || "firm-demo"), witnesses: process.env.HIVE_WITNESS ? [process.env.HIVE_WITNESS] : [] });
const rl = readline.createInterface({ input: process.stdin });
const out = m => process.stdout.write(JSON.stringify(m) + "\n");
const TEN = { "1M": "BC_1MONTH", "3M": "BC_3MONTH", "6M": "BC_6MONTH", "1Y": "BC_1YEAR", "2Y": "BC_2YEAR", "5Y": "BC_5YEAR", "10Y": "BC_10YEAR", "30Y": "BC_30YEAR" };
const tools = [{ name: "get_par_yield", description: "U.S. Treasury daily par yield curve rate for one tenor and date (percent), from home.treasury.gov.", inputSchema: { type: "object", properties: { tenor: { type: "string", description: "e.g. 10Y" }, date: { type: "string", description: "YYYY-MM-DD" } }, required: ["tenor", "date"] } }];
rl.on("line", async l => {
  let m; try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "initialize") return out({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "us-treasury", version: "0.1.0" } } });
  if (m.method === "tools/list") return out({ jsonrpc: "2.0", id: m.id, result: { tools } });
  if (m.method === "tools/call") {
    const a = m.params.arguments || {};
    const date = String(a.date || "").slice(0, 10), tag = TEN[String(a.tenor || "").toUpperCase()] || "BC_10YEAR";
    const url = `https://home.treasury.gov/resource-center/data-chart-center/interest-rates/pages/xml?data=daily_treasury_yield_curve&field_tdr_date_value_month=${date.slice(0, 4)}${date.slice(5, 7)}`;
    const raw = await (await fetch(url)).text();
    const entry = raw.split("<entry>").find(e => e.includes(">" + date + "T00:00:00<"));
    const v = entry ? (new RegExp("<d:" + tag + "[^>]*>([^<]+)</d:" + tag + ">").exec(entry) || [])[1] : null;
    const body = { tenor: String(a.tenor).toUpperCase(), date, value: v, units: "percent", source: "U.S. Department of the Treasury, daily par yield curve rates", source_url: url, source_sha256: crypto.createHash("sha256").update(raw).digest("hex") };
    const delivery = await log.deliver({ tool: m.params.name, datasets: ["treasury.par-yield." + body.tenor], body });
    return out({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: JSON.stringify({ ...body, delivery }) }] } });
  }
  out({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "unknown method" } });
});
