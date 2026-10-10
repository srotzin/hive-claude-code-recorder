// Hive witness for hive.agent-action/1 records.
// It signs "this recorder key had a record of N lines ending in this head, at this time".
// It never receives prompts, tool input, tool output or file content.
//
// Memory: with DATABASE_URL set, it keeps every statement it signs (the four fingerprints, its time,
// its key and its signature) and serves them back by recorder key and session fingerprint, so a
// reviewer can ask the witness directly instead of trusting whoever handed over the record.
// Without DATABASE_URL it remembers nothing and has no dependencies.
import http from "node:http";
import crypto from "node:crypto";
import { canon, WITNESS_FORMAT } from "./core.mjs";

const seed = process.env.WITNESS_ED25519_SEED; // 32 bytes, hex
if (!seed || !/^[0-9a-f]{64}$/.test(seed)) { console.error("WITNESS_ED25519_SEED (64 hex chars) is required"); process.exit(1); }
const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "hex")]);
const sk = crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" });
const pub = crypto.createPublicKey(sk).export({ format: "jwk" }).x;
const B64 = /^[A-Za-z0-9_-]{43}$/, HEX = /^[0-9a-f]{64}$/;

// ---------- memory ----------
let db = null;
async function openMemory() {
  if (!process.env.DATABASE_URL) return;
  const { default: pg } = await import("pg");
  db = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 4, ssl: process.env.DATABASE_SSL === "off" ? false : process.env.DATABASE_URL.includes("render.com") ? { rejectUnauthorized: false } : undefined });
  await db.query(`CREATE TABLE IF NOT EXISTS witness_statements (
    recorder_key text NOT NULL, session_fp text NOT NULL, count integer NOT NULL, head text NOT NULL,
    witnessed_at timestamptz NOT NULL, witnessed_at_text text NOT NULL, witness_key text NOT NULL, sig text PRIMARY KEY)`);
  await db.query(`CREATE INDEX IF NOT EXISTS witness_by_session ON witness_statements (recorder_key, session_fp, count)`);
}
async function remember(st) {
  if (!db) return false;
  await db.query(`INSERT INTO witness_statements VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (sig) DO NOTHING`,
    [st.recorder_key, st.session_fp, st.count, st.head, st.witnessed_at, st.witnessed_at, st.witness_key, st.sig]);
  return true;
}
async function recall(recorder_key, session_fp) {
  const r = await db.query(`SELECT recorder_key, session_fp, count, head, witnessed_at_text, witness_key, sig FROM witness_statements
    WHERE recorder_key = $1 AND session_fp = $2 ORDER BY count, witnessed_at LIMIT 20000`, [recorder_key, session_fp]);
  // Rebuilt exactly as signed, so each one verifies on its own.
  return r.rows.map(x => ({ v: WITNESS_FORMAT, recorder_key: x.recorder_key, session_fp: x.session_fp, count: x.count, head: x.head, witnessed_at: x.witnessed_at_text, witness_key: x.witness_key, sig: x.sig }));
}

const send = (res, code, obj, extra = {}) => { res.writeHead(code, { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "access-control-expose-headers": "x-witness-remembered", "cache-control": "no-store", ...extra }); res.end(JSON.stringify(obj, null, 1)); };

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") return send(res, 204, {});
  if (req.method === "GET" && (u.pathname === "/health" || u.pathname === "/")) return send(res, 200, { ok: true, service: "hive-witness", format: WITNESS_FORMAT, witness_key: pub, memory: !!db });
  if (req.method === "GET" && u.pathname === "/v1/witness/key") return send(res, 200, { format: WITNESS_FORMAT, alg: "Ed25519", witness_key: pub, memory: !!db, note: "Hive holds this witness key. It is a second party to the customer's own recorder key, not an independent auditor." });
  if (req.method === "GET" && u.pathname === "/v1/witness/statements") {
    const rk = u.searchParams.get("recorder_key") || "", sf = u.searchParams.get("session_fp") || "";
    if (!B64.test(rk) || !HEX.test(sf)) return send(res, 400, { error: "give recorder_key (43 base64url characters) and session_fp (64 hex)" });
    if (!db) return send(res, 501, { error: "this witness keeps no memory" });
    try { const statements = await recall(rk, sf); return send(res, 200, { format: WITNESS_FORMAT, witness_key: pub, recorder_key: rk, session_fp: sf, statements }); }
    catch { return send(res, 503, { error: "memory unavailable, try again" }); }
  }
  if (req.method === "POST" && u.pathname === "/v1/witness") {
    let raw = "";
    req.on("data", c => { raw += c; if (raw.length > 4096) req.destroy(); });
    req.on("end", async () => {
      let b; try { b = JSON.parse(raw); } catch { return send(res, 400, { error: "body must be JSON" }); }
      const keys = Object.keys(b || {}).sort().join(",");
      if (keys !== "count,head,recorder_key,session_fp") return send(res, 400, { error: "send exactly recorder_key, session_fp, count and head" });
      if (!B64.test(b.recorder_key) || !HEX.test(b.session_fp) || !HEX.test(b.head) || !Number.isInteger(b.count) || b.count < 1) return send(res, 400, { error: "bad field format" });
      const st = { v: WITNESS_FORMAT, recorder_key: b.recorder_key, session_fp: b.session_fp, count: b.count, head: b.head, witnessed_at: new Date().toISOString(), witness_key: pub };
      st.sig = crypto.sign(null, Buffer.from(canon(st)), sk).toString("base64url");
      let kept = false; try { kept = await remember(st); } catch (e) { console.error("memory write failed", e.message); }
      send(res, 200, st, { "x-witness-remembered": String(kept) });
    });
    return;
  }
  send(res, 404, { error: "not found", try: ["/health", "/v1/witness/key", "POST /v1/witness", "GET /v1/witness/statements?recorder_key=&session_fp="] });
});

openMemory().catch(e => { console.error("memory unavailable:", e.message); db = null; })
  .finally(() => server.listen(process.env.PORT || 8787, () => console.log("hive-witness on", process.env.PORT || 8787, "key", pub, db ? "with memory" : "without memory")));
