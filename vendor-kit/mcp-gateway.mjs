#!/usr/bin/env node
// Zero-code delivery log for a vendor's MCP server. Runs in the vendor's own infrastructure, in front
// of its Streamable HTTP endpoint, with a key the vendor holds. The vendor's server is not changed.
//
// For every successful tools/call result it:
//   1. signs and chains a delivery line (delivery-log.mjs) and has the witness countersign it,
//   2. only then lets the result out, with the delivery id added under
//      result._meta["com.thehiveryiq/delivery"] (namespaced, as MCP allows) and, by default, as one more
//      text block so a customer's recorder sees it even where a client drops _meta.
// Everything else (initialize, tools/list, notifications, errors, progress events) passes through as is.
// JSON responses are buffered (they are bounded); SSE streams are passed through event by event and
// only the event that answers the tools/call is held until it is witnessed.
//
//   node mcp-gateway.mjs --config gateway.json
//   gateway.json: { "port": 8812, "upstream": "http://127.0.0.1:8811/mcp", "vendor": "market-data",
//                   "key": "/path/vendor.pem", "logs": "/path/dir", "witnesses": ["https://witness.thehiveryiq.com/v1/witness"],
//                   "customers": { "<sha256 of bearer token>": "firm-demo" }, "default_customer": null,
//                   "dataset_arg": "dataset", "id_in_content": true, "fail": "closed" | "open",
//                   "commit": { "<tool>": { "dataset": "bonds.evaluated-pricing", "rows": "rows", "id": "cusip", "value": "yield_pct", "scale": 1000 } } }
// With a commit profile for a tool, the signed delivery line also carries a Poseidon commitment to the delivered
// values (lib/commit.mjs), and the random salt goes back only to the customer, in _meta and in the extra text
// block. With the values and the salt the customer can later prove a calculation over exactly those values
// (passport/) without showing them; without the salt nobody can test guesses against the commitment.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { openDeliveryLog } from "./delivery-log.mjs";
import { commitRows, saltToText } from "./lib/commit.mjs";

const NS = "com.thehiveryiq/delivery";
const sha = s => crypto.createHash("sha256").update(s).digest("hex");

export function startGateway(cfg) {
  const logs = new Map(), queues = new Map();
  // One delivery at a time per log, so two calls arriving together never take the same sequence number.
  const serial = (k, fn) => { const p = (queues.get(k) || Promise.resolve()).then(fn, fn); queues.set(k, p.catch(() => {})); return p; };
  const logFor = customer => {
    if (!logs.has(customer)) logs.set(customer, openDeliveryLog({ file: path.join(cfg.logs, `${cfg.vendor}.${customer}.jsonl`), keyPem: cfg.key, vendor: cfg.vendor, customer, log: `${cfg.vendor}/${customer}`, witnesses: cfg.witnesses || [], timeoutMs: cfg.timeout_ms || 8000 }));
    return logs.get(customer);
  };
  const customerOf = req => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
    return (m && cfg.customers && cfg.customers[sha(m[1])]) || cfg.default_customer || null;
  };
  // Adds the delivery to one JSON-RPC response for a tools/call. Returns the new message, or a JSON-RPC
  // error when the gateway is set to fail closed and no witness countersigned.
  async function stamp(msg, call, customer) {
    if (!msg || msg.id === undefined || msg.error || !msg.result || msg.result.isError) return msg;
    const a = call.params?.arguments || {}, tool = call.params?.name;
    const prof = cfg.commit && cfg.commit[tool];
    const datasets = [String(a[cfg.dataset_arg || "dataset"] ?? (prof && prof.dataset) ?? tool)];
    const log = logFor(customer);
    // What was delivered, as data: structured content if the server gives it, else a single JSON text block parsed.
    let body = msg.result.structuredContent;
    if (body === undefined) { const t = (msg.result.content || []).filter(x => x.type === "text"); try { body = t.length === 1 ? JSON.parse(t[0].text) : msg.result.content; } catch { body = msg.result.content; } }
    const closed = (cfg.witnesses || []).length > 0 && cfg.fail !== "open";
    let com = null;
    if (prof) { try { com = commitRows(body, prof); } catch (e) { return { jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: "delivery not sent: " + e.message } }; } }
    const d = await serial(customer, () => log.deliverFull({ tool, datasets, body, requireWitness: closed, commitment: com && com.commitment, commitmentSalt: com && com.salt }));
    if (closed && !d.witnessed)
      return { jsonrpc: "2.0", id: msg.id, error: { code: -32000, message: "delivery not witnessed; the vendor's gateway is set to hold data until it is" } };
    const stampV = { delivery: d.id, log: log.logFp, seq: d.seq, witnessed: d.witnessed, ...(com ? { commitment_salt: saltToText(com.salt) } : {}) };
    const result = { ...msg.result, _meta: { ...(msg.result._meta || {}), [NS]: stampV } };
    if (cfg.id_in_content !== false && Array.isArray(result.content)) result.content = [...result.content, { type: "text", text: JSON.stringify(com ? { delivery: d.id, commitment_salt: saltToText(com.salt) } : { delivery: d.id }) }];
    return { ...msg, result };
  }
  const hopHeaders = new Set(["host", "content-length", "connection", "transfer-encoding", "keep-alive"]);
  const server = http.createServer(async (req, res) => {
    if (process.env.GW_DEBUG) res.on("finish", () => console.log(new Date().toISOString(), req.method, req.url, req.headers.accept || "", "->", res.statusCode));
    const up = new URL(cfg.upstream);
    const headers = Object.fromEntries(Object.entries(req.headers).filter(([k]) => !hopHeaders.has(k)));
    const chunks = []; for await (const c of req) chunks.push(c);
    const raw = Buffer.concat(chunks);
    let call = null; try { const j = JSON.parse(raw.toString("utf8")); if (j && !Array.isArray(j) && j.method === "tools/call" && j.id !== undefined) call = j; } catch {}
    const customer = call ? customerOf(req) : null;
    if (call && !customer) { res.writeHead(401, { "content-type": "application/json" }); return res.end(JSON.stringify({ jsonrpc: "2.0", id: call.id, error: { code: -32001, message: "unknown customer" } })); }
    let upRes;
    try { upRes = await fetch(up, { method: req.method, headers, body: ["GET", "HEAD"].includes(req.method) ? undefined : raw, duplex: "half" }); }
    catch (e) { res.writeHead(502); return res.end(); }
    const out = {}; upRes.headers.forEach((v, k) => { if (!hopHeaders.has(k) && k !== "content-encoding") out[k] = v; });
    const type = upRes.headers.get("content-type") || "";
    if (!call || !upRes.body) { res.writeHead(upRes.status, out); if (upRes.body) for await (const c of upRes.body) res.write(c); return res.end(); }
    if (type.startsWith("application/json")) {
      const text = await upRes.text();
      let msg; try { msg = JSON.parse(text); } catch { res.writeHead(upRes.status, out); return res.end(text); }
      const stamped = await stamp(msg, call, customer);
      const body = JSON.stringify(stamped);
      res.writeHead(upRes.status, { ...out, "content-length": Buffer.byteLength(body) });
      return res.end(body);
    }
    if (type.startsWith("text/event-stream")) {
      res.writeHead(upRes.status, out);
      const dec = new TextDecoder(); let buf = "";
      const flushEvent = async ev => {
        const data = ev.split(/\r?\n/).filter(l => l.startsWith("data:")).map(l => l.slice(5).replace(/^ /, "")).join("\n");
        let msg = null; try { msg = data ? JSON.parse(data) : null; } catch {}
        if (!msg || msg.id !== call.id) return res.write(ev + "\n\n");
        const stamped = await stamp(msg, call, customer);
        const kept = ev.split(/\r?\n/).filter(l => !l.startsWith("data:"));
        res.write([...kept, "data: " + JSON.stringify(stamped)].join("\n") + "\n\n");
      };
      for await (const c of upRes.body) {
        buf += dec.decode(c, { stream: true });
        let m; while ((m = /\r?\n\r?\n/.exec(buf))) { const ev = buf.slice(0, m.index); buf = buf.slice(m.index + m[0].length); await flushEvent(ev); }
      }
      if (buf.trim()) await flushEvent(buf.trim());
      return res.end();
    }
    res.writeHead(upRes.status, out); for await (const c of upRes.body) res.write(c); res.end();
  });
  return new Promise(ok => server.listen(cfg.port, () => ok(server)));
}

if (import.meta.url === "file://" + process.argv[1]) {
  const i = process.argv.indexOf("--config");
  const cfg = JSON.parse(fs.readFileSync(process.argv[i + 1], "utf8"));
  startGateway(cfg).then(() => console.log("hive delivery gateway on", cfg.port, "in front of", cfg.upstream));
}
