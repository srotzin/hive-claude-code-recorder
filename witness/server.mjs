// Hive witness for hive.agent-action/1 records.
// It signs "this recorder key had a record of N lines ending in this head, at this time".
// It never receives prompts, tool input, tool output or file content.
//
// Memory: with DATABASE_URL set, it keeps every statement it signs for a request signed with the
// recorder key (req_sig over the four fields) (the four fingerprints, its time,
// its key and its signature) and serves them back by recorder key and session fingerprint, so a
// reviewer can ask the witness directly instead of trusting whoever handed over the record.
// Without DATABASE_URL it remembers nothing and has no dependencies.
import http from "node:http";
import crypto from "node:crypto";
import { canon, WITNESS_FORMAT } from "./core.mjs";
import { makeLog } from "./log.mjs";

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
  await db.query(`ALTER TABLE witness_statements ADD COLUMN IF NOT EXISTS request_signed boolean NOT NULL DEFAULT false`);
}
// Every remembered statement is also appended to the public log (log.mjs) in the same transaction.
let log = null;
const ORIGIN = process.env.WITNESS_LOG_ORIGIN || "witness.thehiveryiq.com/log";
async function remember(st) {
  if (!db) return false;
  const insert = c => c.query(`INSERT INTO witness_statements (recorder_key, session_fp, count, head, witnessed_at, witnessed_at_text, witness_key, sig, request_signed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true) ON CONFLICT (sig) DO NOTHING`,
    [st.recorder_key, st.session_fp, st.count, st.head, st.witnessed_at, st.witnessed_at, st.witness_key, st.sig]);
  if (log) { const idx = await log.rememberAndLog(st, insert); return { idx }; }
  await insert(db);
  return true;
}
async function recall(recorder_key, session_fp) {
  const r = await db.query(`SELECT recorder_key, session_fp, count, head, witnessed_at_text, witness_key, sig FROM witness_statements
    WHERE recorder_key = $1 AND session_fp = $2 AND request_signed ORDER BY count, witnessed_at LIMIT 20000`, [recorder_key, session_fp]);
  // Rebuilt exactly as signed, so each one verifies on its own.
  return r.rows.map(x => ({ v: WITNESS_FORMAT, recorder_key: x.recorder_key, session_fp: x.session_fp, count: x.count, head: x.head, witnessed_at: x.witnessed_at_text, witness_key: x.witness_key, sig: x.sig }));
}

// Every session the witness remembers for one recorder key, so a usage statement that leaves one
// out can be caught. Only fingerprints: session_fp, how many lines, the last head and when.
async function sessions(recorder_key, from, to) {
  const r = await db.query(`SELECT DISTINCT ON (session_fp) session_fp, count, head, witnessed_at_text,
      (SELECT min(witnessed_at_text) FROM witness_statements w2 WHERE w2.recorder_key = w.recorder_key AND w2.session_fp = w.session_fp AND w2.request_signed) AS first_at
    FROM witness_statements w WHERE recorder_key = $1 AND request_signed AND witnessed_at >= $2 AND witnessed_at <= $3
    ORDER BY session_fp, count DESC, witnessed_at DESC LIMIT 5000`, [recorder_key, from, to]);
  return r.rows.map(x => ({ session_fp: x.session_fp, count: x.count, head: x.head, first_at: x.first_at, last_at: x.witnessed_at_text }));
}

const send = (res, code, obj, extra = {}) => { res.writeHead(code, { "content-type": "application/json", "access-control-allow-origin": "*", "access-control-allow-headers": "content-type", "access-control-expose-headers": "x-witness-remembered, x-witness-log-index", "cache-control": "no-store", ...extra }); res.end(JSON.stringify(obj, null, 1)); };

const sendBytes = (res, code, bytes, type = "application/cose", extra = {}) => { res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "access-control-expose-headers": "location", "cache-control": "no-store", ...extra }); res.end(Buffer.from(bytes)); };
const sendText = (res, code, text, type = "text/plain; charset=utf-8") => { res.writeHead(code, { "content-type": type, "access-control-allow-origin": "*", "cache-control": "no-store" }); res.end(text); };
const int = (v, d) => v === null || v === "" ? d : /^\d{1,9}$/.test(v) ? Number(v) : NaN;
const readBody = (req, max) => new Promise((ok, bad) => { const parts = []; let n = 0; req.on("data", c => { n += c.length; if (n > max) { bad(new Error("too large")); req.destroy(); } else parts.push(c); }); req.on("end", () => ok(Buffer.concat(parts))); req.on("error", bad); });

async function logRoutes(req, res, u) {
  const p = u.pathname, n = log.size();
  if (req.method === "GET" && p === "/v1/witness/log/head") {
    const size = int(u.searchParams.get("tree_size"), n);
    if (!(size >= 0 && size <= n)) return send(res, 400, { error: "tree_size must be between 0 and " + n });
    return send(res, 200, log.head(size));
  }
  if (req.method === "GET" && p === "/v1/witness/log/checkpoint") {
    const size = int(u.searchParams.get("tree_size"), n);
    if (!(size >= 1 && size <= n)) return send(res, 400, { error: "tree_size must be between 1 and " + n });
    return sendText(res, 200, await log.checkpoint(size));
  }
  if (req.method === "GET" && p === "/v1/witness/log/cosignatures") {
    const size = int(u.searchParams.get("tree_size"), null);
    return send(res, 200, { origin: ORIGIN, cosignatures: await log.cosignatures(Number.isNaN(size) ? null : size) });
  }
  if (req.method === "POST" && p === "/v1/witness/log/cosignatures") {
    let b; try { b = JSON.parse((await readBody(req, 4096)).toString("utf8")); } catch { return send(res, 400, { error: "body must be JSON" }); }
    try { return send(res, 200, await log.addCosignature(b || {})); } catch (e) { return send(res, 400, { error: e.message }); }
  }
  if (req.method === "GET" && p === "/v1/witness/log/proofs") {
    const rk = u.searchParams.get("recorder_key") || "", sf = u.searchParams.get("session_fp") || "", size = int(u.searchParams.get("tree_size"), n);
    if (!B64.test(rk) || !HEX.test(sf) || !(size >= 1 && size <= n)) return send(res, 400, { error: "give recorder_key, session_fp and optionally tree_size (1 to " + n + ")" });
    const found = await log.indexesFor(rk, sf, size);
    return send(res, 200, { head: log.head(size), entries: found.map(x => ({ ...x, path: log.inclusion(x.leaf_index, size) })) });
  }
  if (req.method === "GET" && p === "/v1/witness/log/inclusion") {
    const idx = int(u.searchParams.get("index"), NaN), size = int(u.searchParams.get("tree_size"), n);
    if (!(idx >= 0 && idx < size && size <= n)) return send(res, 400, { error: "need 0 <= index < tree_size <= " + n });
    return send(res, 200, { leaf_index: idx, tree_size: size, path: log.inclusion(idx, size) });
  }
  if (req.method === "GET" && p === "/v1/witness/log/consistency") {
    const a = int(u.searchParams.get("first"), NaN), b = int(u.searchParams.get("second"), n);
    if (!(a >= 1 && a <= b && b <= n)) return send(res, 400, { error: "need 1 <= first <= second <= " + n });
    if (u.searchParams.get("format") === "cose") return sendBytes(res, 200, log.consistencyReceipt(a, b));
    return send(res, 200, { first: a, second: b, path: log.consistency(a, b) });
  }
  if (req.method === "GET" && p === "/v1/witness/log/entries") {
    const start = int(u.searchParams.get("start"), 0), count = Math.min(int(u.searchParams.get("count"), 1000), 1000);
    if (!(start >= 0) || !(count >= 1)) return send(res, 400, { error: "start and count must be whole numbers" });
    return send(res, 200, { origin: ORIGIN, tree_size: n, start, entries: await log.entries(start, count) });
  }
  if (req.method === "GET" && p === "/v1/witness/log/receipt") {
    const idx = int(u.searchParams.get("index"), NaN), size = int(u.searchParams.get("tree_size"), n);
    if (!(idx >= 0 && idx < size && size <= n)) return send(res, 400, { error: "need 0 <= index < tree_size <= " + n });
    return sendBytes(res, 200, await log.receipt(idx, size));
  }
  if (req.method === "GET" && p === "/v1/witness/log") return send(res, 200, { origin: ORIGIN, ...log.stats(), witness_key: pub, registration_policy: log.policy,
    note: "Every statement this witness remembers is in this RFC 9162 tree. Receipts are RFC 9942 COSE Receipts. Hive runs this log; cosignatures from outside parties are what make a split view impossible to hide.",
    endpoints: ["/v1/witness/log/head", "/v1/witness/log/checkpoint", "/v1/witness/log/cosignatures", "/v1/witness/log/proofs?recorder_key=&session_fp=", "/v1/witness/log/inclusion?index=&tree_size=", "/v1/witness/log/consistency?first=&second=[&format=cose]", "/v1/witness/log/entries?start=&count=", "/v1/witness/log/receipt?index=&tree_size=", "POST /entries", "GET /entries/{index}", "/.well-known/scitt-keys"] });
  // SCRAPI (draft-ietf-scitt-scrapi-11)
  if (req.method === "GET" && p === "/.well-known/scitt-keys") return sendBytes(res, 200, log.keySet(), "application/cbor");
  if (req.method === "GET" && p.startsWith("/.well-known/scitt-keys/")) {
    const k = decodeURIComponent(p.slice("/.well-known/scitt-keys/".length));
    const want = log.kid, alt = Buffer.from(want).toString("base64url");
    return k === want || k === alt ? sendBytes(res, 200, log.keyOne(), "application/cbor") : sendBytes(res, 404, new Uint8Array(0), "application/cbor");
  }
  if (req.method === "POST" && p === "/entries") {
    let raw; try { raw = await readBody(req, 20000); } catch { return send(res, 413, { error: "signed statement too large" }); }
    try { const idx = await log.register(new Uint8Array(raw)); return sendBytes(res, 201, await log.receipt(idx), "application/cose", { location: "/entries/" + idx }); }
    catch (e) { return send(res, 400, { error: e.message }); }
  }
  if (req.method === "GET" && /^\/entries\/\d{1,9}$/.test(p)) {
    const idx = Number(p.slice(9));
    if (!(idx < n)) return send(res, 404, { error: "no such entry" });
    return sendBytes(res, 200, await log.receipt(idx));
  }
  return false;
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, "http://x");
  if (req.method === "OPTIONS") return send(res, 204, {});
  if (log && (u.pathname.startsWith("/v1/witness/log") || u.pathname.startsWith("/entries") || u.pathname.startsWith("/.well-known/scitt-keys"))) {
    try { const done = await logRoutes(req, res, u); if (done !== false) return; } catch (e) { console.error("log route", e.message); return send(res, 503, { error: "log unavailable, try again" }); }
  }
  if (req.method === "GET" && (u.pathname === "/health" || u.pathname === "/")) return send(res, 200, { ok: true, service: "hive-witness", format: WITNESS_FORMAT, witness_key: pub, memory: !!db, log: log ? log.stats() : null });
  if (req.method === "GET" && u.pathname === "/v1/witness/key") return send(res, 200, { format: WITNESS_FORMAT, alg: "Ed25519", witness_key: pub, memory: !!db, note: "Hive holds this witness key. It is a second party to the customer's own recorder key, not an independent auditor." });
  if (req.method === "GET" && u.pathname === "/v1/witness/statements") {
    const rk = u.searchParams.get("recorder_key") || "", sf = u.searchParams.get("session_fp") || "";
    if (!B64.test(rk) || !HEX.test(sf)) return send(res, 400, { error: "give recorder_key (43 base64url characters) and session_fp (64 hex)" });
    if (!db) return send(res, 501, { error: "this witness keeps no memory" });
    try { const statements = await recall(rk, sf); return send(res, 200, { format: WITNESS_FORMAT, witness_key: pub, recorder_key: rk, session_fp: sf, statements }); }
    catch { return send(res, 503, { error: "memory unavailable, try again" }); }
  }
  if (req.method === "GET" && u.pathname === "/v1/witness/sessions") {
    const rk = u.searchParams.get("recorder_key") || "";
    const from = new Date(u.searchParams.get("from") || 0), to = new Date(u.searchParams.get("to") || Date.now() + 864e5);
    if (!B64.test(rk) || isNaN(from) || isNaN(to)) return send(res, 400, { error: "give recorder_key (43 base64url characters), and optionally from and to as ISO times" });
    if (!db) return send(res, 501, { error: "this witness keeps no memory" });
    try { return send(res, 200, { format: WITNESS_FORMAT, witness_key: pub, recorder_key: rk, from: from.toISOString(), to: to.toISOString(), sessions: await sessions(rk, from, to) }); }
    catch { return send(res, 503, { error: "memory unavailable, try again" }); }
  }
  if (req.method === "POST" && u.pathname === "/v1/witness") {
    let raw = "";
    req.on("data", c => { raw += c; if (raw.length > 4096) req.destroy(); });
    req.on("end", async () => {
      let b; try { b = JSON.parse(raw); } catch { return send(res, 400, { error: "body must be JSON" }); }
      const keys = Object.keys(b || {}).sort().join(",");
      if (keys !== "count,head,recorder_key,session_fp" && keys !== "count,head,recorder_key,req_sig,session_fp") return send(res, 400, { error: "send exactly recorder_key, session_fp, count and head, and optionally req_sig" });
      if (!B64.test(b.recorder_key) || !HEX.test(b.session_fp) || !HEX.test(b.head) || !Number.isInteger(b.count) || b.count < 1) return send(res, 400, { error: "bad field format" });
      // Only a request signed with the recorder key itself is remembered, so nobody else can add a
      // history to someone's session. An unsigned request is still witnessed, and not remembered.
      let signedReq = false;
      if (b.req_sig !== undefined) {
        try {
          const rk = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: b.recorder_key }, format: "jwk" });
          signedReq = typeof b.req_sig === "string" && crypto.verify(null, Buffer.from(canon({ count: b.count, head: b.head, recorder_key: b.recorder_key, session_fp: b.session_fp })), rk, Buffer.from(b.req_sig, "base64url"));
        } catch {}
        if (!signedReq) return send(res, 400, { error: "req_sig does not verify against recorder_key" });
      }
      const st = { v: WITNESS_FORMAT, recorder_key: b.recorder_key, session_fp: b.session_fp, count: b.count, head: b.head, witnessed_at: new Date().toISOString(), witness_key: pub };
      st.sig = crypto.sign(null, Buffer.from(canon(st)), sk).toString("base64url");
      let kept = false; try { if (signedReq) kept = await remember(st); } catch (e) { console.error("memory write failed", e.message); }
      send(res, 200, st, { "x-witness-remembered": String(!!kept), ...(kept && kept.idx !== undefined && kept.idx !== null ? { "x-witness-log-index": String(kept.idx) } : {}) });
    });
    return;
  }
  send(res, 404, { error: "not found", try: ["/health", "/v1/witness/key", "/v1/witness/log", "POST /v1/witness", "GET /v1/witness/statements?recorder_key=&session_fp=", "GET /v1/witness/sessions?recorder_key=&from=&to="] });
});

openMemory().then(async () => { if (db) { const l = makeLog({ db, sk, pub, origin: ORIGIN }); await l.open(); log = l; console.log("log open, tree size", l.size()); } })
  .catch(e => console.error("memory or log unavailable:", e.message))
  .finally(() => server.listen(process.env.PORT || 8787, () => console.log("hive-witness on", process.env.PORT || 8787, "key", pub, db ? "with memory" : "without memory")));
