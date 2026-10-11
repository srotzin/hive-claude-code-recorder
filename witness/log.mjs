// The witness's public log. Every statement the witness remembers is appended, in order, to one
// RFC 9162 Merkle tree. Anyone can ask for the current tree head, an inclusion proof for any
// statement, and a consistency proof between any two sizes, so the witness cannot quietly show one
// party one history and another party a different one: two heads that do not extend each other are
// both signed by the witness key, which is proof of the split.
//
// Formats:
//   tree head (JSON)   hive.witness-tree-head/1 {tree_size, root_hash, timestamp, origin, witness_key, sig}
//   checkpoint         c2sp.org/tlog-checkpoint signed note, with c2sp.org/tlog-cosignature lines from
//                      outside cosigners (ICE, the firm) who check consistency before they sign
//   receipts           RFC 9942 COSE Receipts (vds 1, RFC9162_SHA256), detached root payload
//   registration       SCITT (RFC 9943) Signed Statements via SCRAPI POST /entries
import crypto from "node:crypto";
import * as M from "./merkle.mjs";
import * as C from "./cose.mjs";
import { canon } from "./core.mjs";

export const HEAD_FORMAT = "hive.witness-tree-head/1";
const H = u => new Uint8Array(crypto.createHash("sha256").update(u).digest());
const te = new TextEncoder();
const b64u = u => Buffer.from(u).toString("base64url"), b64 = u => Buffer.from(u).toString("base64");

export function makeLog({ db, sk, pub, origin }) {
  const leaves = [], memo = new Map(), kinds = [];
  const pubRaw = Buffer.from(pub, "base64url"), kid = te.encode(pub);
  const sign = bytes => new Uint8Array(crypto.sign(null, Buffer.from(bytes), sk));
  // c2sp.org/signed-note key id: SHA-256(name || 0x0A || 0x01 || pubkey)[:4]
  const noteKeyId = H(new Uint8Array([...te.encode(origin), 0x0a, 0x01, ...pubRaw])).slice(0, 4);
  let queue = Promise.resolve();

  async function open() {
    await db.query(`CREATE TABLE IF NOT EXISTS witness_log (idx integer PRIMARY KEY, kind text NOT NULL, entry text NOT NULL,
      leaf_hash text NOT NULL, ref text UNIQUE NOT NULL, added_at timestamptz NOT NULL DEFAULT now())`);
    await db.query(`CREATE TABLE IF NOT EXISTS witness_cosignatures (tree_size integer NOT NULL, root_hash text NOT NULL,
      name text NOT NULL, cosigner_key text NOT NULL, line text NOT NULL, signed_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (tree_size, cosigner_key))`);
    const c = await db.query(`SELECT count(*)::int AS n FROM witness_log`);
    if (c.rows[0].n === 0) await backfill();
    const r = await db.query(`SELECT idx, kind, leaf_hash FROM witness_log ORDER BY idx`);
    for (const x of r.rows) { if (x.idx !== leaves.length) throw new Error("log has a gap at " + leaves.length); leaves.push(M.fromHex(x.leaf_hash)); kinds.push(x.kind); }
    if (!kinds.includes("policy")) await registerPolicy();
  }
  // One time: every statement remembered before the log existed goes in first, in the order it was witnessed.
  async function backfill() {
    const r = await db.query(`SELECT recorder_key, session_fp, count, head, witnessed_at_text, witness_key, sig FROM witness_statements
      WHERE request_signed ORDER BY witnessed_at, sig`);
    let idx = 0;
    for (let i = 0; i < r.rows.length; i += 400) {
      const rows = r.rows.slice(i, i + 400), vals = [], args = [];
      for (const x of rows) {
        const st = { v: "hive.agent-action-witness/1", recorder_key: x.recorder_key, session_fp: x.session_fp, count: x.count, head: x.head, witnessed_at: x.witnessed_at_text, witness_key: x.witness_key, sig: x.sig };
        const entry = canon(st);
        args.push(idx++, "statement", entry, M.toHex(M.leafHash(H, te.encode(entry))), "st:" + x.sig);
        vals.push(`($${args.length - 4},$${args.length - 3},$${args.length - 2},$${args.length - 1},$${args.length})`);
      }
      if (rows.length) await db.query(`INSERT INTO witness_log (idx, kind, entry, leaf_hash, ref) VALUES ${vals.join(",")}`, args);
    }
  }
  // Appends inside the caller's transaction. Caller holds the advisory lock.
  async function appendTx(client, kind, entryText, entryBytes, ref) {
    const r = await client.query(`SELECT coalesce(max(idx) + 1, 0)::int AS n FROM witness_log`);
    const idx = r.rows[0].n, leaf = M.leafHash(H, entryBytes);
    await client.query(`INSERT INTO witness_log (idx, kind, entry, leaf_hash, ref) VALUES ($1,$2,$3,$4,$5)`, [idx, kind, entryText, M.toHex(leaf), ref]);
    return { idx, leaf };
  }
  const commitLeaf = (idx, leaf, kind) => { if (idx !== leaves.length) throw new Error("log out of step"); leaves.push(leaf); kinds.push(kind); };
  // Serialised so leaves[] stays in the same order as the table.
  function serial(fn) { const p = queue.then(fn, fn); queue = p.catch(() => {}); return p; }

  // Remember a witness statement and log it in one transaction, so nothing is remembered and not logged.
  function rememberAndLog(st, insertStatement) {
    return serial(async () => {
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock(424242)");
        const ins = await insertStatement(client);
        let out = null;
        if (ins.rowCount === 1) { const entry = canon(st); out = await appendTx(client, "statement", entry, te.encode(entry), "st:" + st.sig); }
        await client.query("COMMIT");
        if (out) commitLeaf(out.idx, out.leaf, "statement");
        return out ? out.idx : null;
      } catch (e) { await client.query("ROLLBACK").catch(() => {}); throw e; } finally { client.release(); }
    });
  }

  const size = () => leaves.length;
  const rootAt = n => M.rootOf(H, leaves, 0, n, memo);
  function head(n = size()) {
    const h = { v: HEAD_FORMAT, origin, tree_size: n, root_hash: M.toHex(rootAt(n)), timestamp: new Date().toISOString(), witness_key: pub };
    h.sig = b64u(sign(te.encode(canon(h))));
    return h;
  }
  // c2sp.org/tlog-checkpoint body, signed as a c2sp.org/signed-note.
  const checkpointBody = n => `${origin}\n${n}\n${b64(rootAt(n))}\n`;
  async function checkpoint(n = size()) {
    const body = checkpointBody(n);
    const lines = [`\u2014 ${origin} ${b64(new Uint8Array([...noteKeyId, ...sign(te.encode(body))]))}`];
    const cs = await db.query(`SELECT line FROM witness_cosignatures WHERE tree_size = $1 AND root_hash = $2 ORDER BY name`, [n, M.toHex(rootAt(n))]);
    for (const x of cs.rows) lines.push(x.line);
    return body + "\n" + lines.join("\n") + "\n";
  }
  // A cosigner posts back the line it signed. Checked here, then served with the checkpoint.
  //   line: "\u2014 <name> base64(keyid4 || timestamp8 || sig64)" over "cosignature/v1\ntime <t>\n" + body
  async function addCosignature({ name, cosigner_key, tree_size, line }) {
    if (!Number.isInteger(tree_size) || tree_size < 1 || tree_size > size()) throw new Error("unknown tree size");
    if (!/^[A-Za-z0-9_-]{43}$/.test(cosigner_key) || !/^[\x21-\x7e]{1,128}$/.test(name)) throw new Error("bad cosigner name or key");
    const m = /^\u2014 (\S+) ([A-Za-z0-9+/=]+)$/.exec(line || "");
    if (!m || m[1] !== name) throw new Error("bad cosignature line");
    const raw = Buffer.from(m[2], "base64"), ck = Buffer.from(cosigner_key, "base64url");
    if (raw.length !== 76) throw new Error("cosignature must be 76 bytes");
    const want = H(new Uint8Array([...te.encode(name), 0x0a, 0x04, ...ck])).slice(0, 4);
    if (!raw.subarray(0, 4).equals(Buffer.from(want))) throw new Error("cosignature key id does not match");
    const t = Number(raw.readBigUInt64BE(4));
    const msg = te.encode(`cosignature/v1\ntime ${t}\n` + checkpointBody(tree_size));
    const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: cosigner_key }, format: "jwk" });
    if (!crypto.verify(null, msg, key, raw.subarray(12))) throw new Error("cosignature does not verify");
    await db.query(`INSERT INTO witness_cosignatures (tree_size, root_hash, name, cosigner_key, line) VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (tree_size, cosigner_key) DO UPDATE SET line = EXCLUDED.line, signed_at = now()`, [tree_size, M.toHex(rootAt(tree_size)), name, cosigner_key, line]);
    return { tree_size, name, time: t };
  }
  async function cosignatures(n) {
    const r = await db.query(`SELECT tree_size, root_hash, name, cosigner_key, line, signed_at FROM witness_cosignatures
      WHERE ($1::int IS NULL OR tree_size = $1) ORDER BY tree_size DESC, name LIMIT 200`, [n ?? null]);
    return r.rows.map(x => ({ tree_size: x.tree_size, root_hash: x.root_hash, name: x.name, cosigner_key: x.cosigner_key, line: x.line, signed_at: x.signed_at.toISOString() }));
  }

  const inclusion = (idx, n = size()) => M.inclusionPath(H, leaves, idx, 0, n, memo).map(M.toHex);
  const consistency = (m, n = size()) => M.consistencyPath(H, leaves, m, n, memo).map(M.toHex);
  async function entries(start, count) {
    const r = await db.query(`SELECT idx, kind, entry FROM witness_log WHERE idx >= $1 AND idx < $2 ORDER BY idx`, [start, start + count]);
    return r.rows.map(x => ({ index: x.idx, kind: x.kind, entry: x.entry }));
  }
  async function indexesFor(recorder_key, session_fp, n) {
    const r = await db.query(`SELECT l.idx, s.sig FROM witness_log l JOIN witness_statements s ON l.ref = 'st:' || s.sig
      WHERE s.recorder_key = $1 AND s.session_fp = $2 AND s.request_signed AND l.idx < $3 ORDER BY l.idx`, [recorder_key, session_fp, n]);
    return r.rows.map(x => ({ sig: x.sig, leaf_index: x.idx }));
  }
  async function subjectOf(idx) {
    const r = await db.query(`SELECT kind, entry FROM witness_log WHERE idx = $1`, [idx]);
    if (!r.rows.length) return null;
    const x = r.rows[0];
    if (x.kind === "statement") return JSON.parse(x.entry).session_fp;
    try { const ss = C.decode(Buffer.from(x.entry, "base64url")); const cwt = C.decode(ss.value[0]).get(15); return String(cwt.get(2)); } catch { return "entry-" + idx; }
  }
  // RFC 9942 inclusion receipt for one leaf at tree size n.
  async function receipt(idx, n = size()) {
    if (!(idx < n && n <= size())) throw new Error("leaf index must be below tree size");
    const sub = await subjectOf(idx);
    const path = M.inclusionPath(H, leaves, idx, 0, n, memo);
    return C.makeReceipt({ kid, iss: "https://" + origin.split("/")[0], sub, root: rootAt(n), proofType: C.P_INCLUSION, proof: C.inclusionProof(n, idx, path), sign });
  }
  // RFC 9942 consistency receipt from size m to n. The payload is the newer root.
  function consistencyReceipt(m, n = size()) {
    if (!(m >= 1 && m <= n && n <= size())) throw new Error("need 1 <= first <= second <= tree size");
    const path = M.consistencyPath(H, leaves, m, n, memo);
    return C.makeReceipt({ kid, iss: "https://" + origin.split("/")[0], sub: "consistency " + m + " " + n, root: rootAt(n), proofType: C.P_CONSISTENCY, proof: C.consistencyProof(m, n, path), sign });
  }

  // SCITT registration. Registration policy: tagged COSE_Sign1, alg EdDSA, kid is the signer's Ed25519
  // public key (43 base64url characters, as bytes), CWT claims with iss and sub, a content type, an
  // attached payload of at most 16 KB, and a signature that verifies with kid.
  const POLICY = { v: "hive.witness-registration-policy/1", accepts: "COSE_Sign1 Signed Statements", alg: "EdDSA (-8), Ed25519",
    kid: "the signer's Ed25519 public key, 43 base64url characters, as a byte string", headers_required: ["1 alg", "3 content type", "4 kid", "15 CWT claims with 1 iss and 2 sub"],
    payload: "attached, at most 16384 bytes", unprotected: "emptied before the statement is appended", leaf: "SHA-256(0x00 || the COSE_Sign1 bytes with an empty unprotected map)" };
  function checkSignedStatement(bytes) {
    if (bytes.length > 20000) throw new Error("signed statement too large");
    const t = C.decode(bytes);
    if (!(t instanceof C.Tag) || t.tag !== 18 || !Array.isArray(t.value) || t.value.length !== 4) throw new Error("not a tagged COSE_Sign1");
    const [prot, , payload, sig] = t.value;
    if (!(prot instanceof Uint8Array) || !(payload instanceof Uint8Array) || !(sig instanceof Uint8Array)) throw new Error("payload must be attached");
    if (payload.length > 16384) throw new Error("payload larger than 16384 bytes");
    const ph = C.decode(prot);
    if (!(ph instanceof Map) || ph.get(1) !== C.ALG_EDDSA) throw new Error("alg must be EdDSA (-8)");
    const k = ph.get(4); if (!(k instanceof Uint8Array)) throw new Error("kid is required");
    const kidText = new TextDecoder().decode(k);
    if (!/^[A-Za-z0-9_-]{43}$/.test(kidText)) throw new Error("kid must be an Ed25519 public key in base64url");
    if (ph.get(3) === undefined) throw new Error("content type (3) is required");
    const cwt = ph.get(15); if (!(cwt instanceof Map) || !cwt.get(1) || !cwt.get(2)) throw new Error("CWT claims (15) with iss and sub are required");
    const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: kidText }, format: "jwk" });
    const tbs = C.encode(["Signature1", prot, new Uint8Array(0), payload]);
    if (!crypto.verify(null, tbs, key, sig)) throw new Error("signature does not verify with kid");
    return C.encode(new C.Tag(18, [prot, new Map(), payload, sig]));
  }
  function register(bytes, kind = "scitt") {
    const entry = checkSignedStatement(bytes);
    const ref = "cose:" + M.toHex(H(entry));
    return serial(async () => {
      const client = await db.connect();
      try {
        await client.query("BEGIN");
        await client.query("SELECT pg_advisory_xact_lock(424242)");
        const ex = await client.query(`SELECT idx FROM witness_log WHERE ref = $1`, [ref]);
        if (ex.rows.length) { await client.query("COMMIT"); return ex.rows[0].idx; }
        const out = await appendTx(client, kind, b64u(entry), entry, ref);
        await client.query("COMMIT");
        commitLeaf(out.idx, out.leaf, kind);
        return out.idx;
      } catch (e) { await client.query("ROLLBACK").catch(() => {}); throw e; } finally { client.release(); }
    });
  }
  // RFC 9943: the registration policy is itself registered as a Signed Statement, signed by the witness.
  async function registerPolicy() {
    const prot = C.encode(new Map([[1, C.ALG_EDDSA], [3, "application/json"], [4, kid], [15, new Map([[1, "https://" + origin.split("/")[0]], [2, "registration-policy"]])]]));
    const payload = te.encode(canon(POLICY));
    const sig = sign(C.encode(["Signature1", prot, new Uint8Array(0), payload]));
    return register(C.encode(new C.Tag(18, [prot, new Map(), payload, sig])), "policy");
  }
  // SCRAPI key set: COSE_KeySet of one OKP Ed25519 key.
  const coseKey = () => new Map([[1, 1], [2, kid], [3, C.ALG_EDDSA], [-1, 6], [-2, new Uint8Array(pubRaw)]]);
  const keySet = () => C.encode([coseKey()]);
  const keyOne = () => C.encode(coseKey());
  const stats = () => ({ tree_size: size(), statements: kinds.filter(k => k === "statement").length, scitt: kinds.filter(k => k === "scitt").length, policy: kinds.filter(k => k === "policy").length });

  return { open, rememberAndLog, size, head, checkpoint, addCosignature, cosignatures, inclusion, consistency, entries, indexesFor, receipt, consistencyReceipt, register, keySet, keyOne, kid: pub, policy: POLICY, stats };
}
