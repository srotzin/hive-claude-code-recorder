// Hive witness for hive.agent-action/1 records. Stateless and dependency free.
// It signs "this recorder key had a record of N lines ending in this head, at this time".
// It never receives prompts, tool input, tool output or file content, and it stores nothing.
import http from "node:http";
import crypto from "node:crypto";
import { canon, WITNESS_FORMAT } from "./core.mjs";

const seed = process.env.WITNESS_ED25519_SEED; // 32 bytes, hex
if (!seed || !/^[0-9a-f]{64}$/.test(seed)) { console.error("WITNESS_ED25519_SEED (64 hex chars) is required"); process.exit(1); }
const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "hex")]);
const sk = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
const pub = crypto.createPublicKey(sk).export({ format: "jwk" }).x;
const B64 = /^[A-Za-z0-9_-]{43}$/, HEX = /^[0-9a-f]{64}$/;

const send = (res, code, obj) => { res.writeHead(code, { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "cache-control": "no-store" }); res.end(JSON.stringify(obj, null, 1)); };

http.createServer((req, res) => {
  const u = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") return send(res, 204, {});
  if (req.method === "GET" && (u.pathname === "/health" || u.pathname === "/")) return send(res, 200, { ok: true, service: "hive-witness", format: WITNESS_FORMAT, witness_key: pub });
  if (req.method === "GET" && u.pathname === "/v1/witness/key") return send(res, 200, { format: WITNESS_FORMAT, alg: "Ed25519", witness_key: pub, note: "Hive holds this witness key. It is a second party to the customer's own recorder key, not an independent auditor." });
  if (req.method === "POST" && u.pathname === "/v1/witness") {
    let raw = "";
    req.on("data", c => { raw += c; if (raw.length > 4096) req.destroy(); });
    req.on("end", () => {
      let b; try { b = JSON.parse(raw); } catch { return send(res, 400, { error: "body must be JSON" }); }
      const keys = Object.keys(b || {}).sort().join(",");
      if (keys !== "count,head,recorder_key,session_fp") return send(res, 400, { error: "send exactly recorder_key, session_fp, count and head" });
      if (!B64.test(b.recorder_key) || !HEX.test(b.session_fp) || !HEX.test(b.head) || !Number.isInteger(b.count) || b.count < 1) return send(res, 400, { error: "bad field format" });
      const st = { v: WITNESS_FORMAT, recorder_key: b.recorder_key, session_fp: b.session_fp, count: b.count, head: b.head, witnessed_at: new Date().toISOString(), witness_key: pub };
      st.sig = crypto.sign(null, Buffer.from(canon(st)), sk).toString("base64url");
      send(res, 200, st);
    });
    return;
  }
  send(res, 404, { error: "not found", try: ["/health", "/v1/witness/key", "POST /v1/witness"] });
}).listen(process.env.PORT || 8787, () => console.log("hive-witness on", process.env.PORT || 8787, "key", pub));
