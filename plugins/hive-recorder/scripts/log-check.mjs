// Checks on the witness's public log (RFC 9162 tree, C2SP checkpoints, RFC 9942 receipts).
// c: { sha256(Uint8Array) -> Uint8Array, verifyBytes(pubB64url, msgBytes, sigBytes) -> bool }
import * as M from "./merkle.mjs";
import * as C from "./cose.mjs";
import { canon } from "./core.mjs";

export const HEAD_FORMAT = "hive.witness-tree-head/1";
const te = new TextEncoder();
const no = (step, why, extra = {}) => ({ ok: false, step, why, ...extra });
const fromB64 = s => { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), ch => ch.charCodeAt(0)); };
const toB64 = u => btoa(String.fromCharCode(...u));
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
export const entryBytes = e => e.kind === "statement" ? te.encode(e.entry) : fromB64(e.entry);
export const statementLeaf = (st, c) => M.leafHash(c.sha256, te.encode(canon(st)));

export function checkHead(h, c, opts = {}) {
  if (!h || h.v !== HEAD_FORMAT || !Number.isInteger(h.tree_size) || !/^[0-9a-f]{64}$/.test(h.root_hash || "")) return no("HEAD", "this is not a " + HEAD_FORMAT + " tree head");
  if (opts.witnessPin && h.witness_key !== opts.witnessPin) return no("HEAD", "the tree head is signed by another key than the pinned witness");
  if (opts.origin && h.origin !== opts.origin) return no("HEAD", "the tree head names another log");
  const { sig, ...b } = h;
  if (!c.verifyBytes(h.witness_key, te.encode(canon(b)), fromB64(sig || ""))) return no("HEAD", "the tree head's signature does not verify");
  return { ok: true };
}

// The witness's memory for one session, checked against its public log: every remembered
// statement must be in the tree under this head, at the index the witness gave.
//   statements: from /v1/witness/statements   proofs: from /v1/witness/log/proofs
export function checkLogged(statements, proofs, c, opts = {}) {
  const h = checkHead(proofs && proofs.head, c, opts);
  if (!h.ok) return h;
  const root = M.fromHex(proofs.head.root_hash), size = proofs.head.tree_size;
  const bySig = new Map((proofs.entries || []).map(e => [e.sig, e]));
  if (bySig.size !== (proofs.entries || []).length) return no("LOGGED", "the log names one statement twice");
  for (const [i, st] of statements.entries()) {
    const e = bySig.get(st.sig);
    if (!e) return no("LOGGED", "statement " + (i + 1) + " (line " + st.count + ") is remembered by the witness but is not in its public log");
    if (!M.verifyInclusion(c.sha256, statementLeaf(st, c), e.leaf_index, size, (e.path || []).map(M.fromHex), root))
      return no("INCLUDED", "statement " + (i + 1) + " (line " + st.count + ") does not prove into the tree head at index " + e.leaf_index);
  }
  const sigs = new Set(statements.map(s => s.sig));
  const extra = (proofs.entries || []).filter(e => !sigs.has(e.sig));
  if (extra.length) return no("LOGGED", "the public log holds " + extra.length + " statement" + (extra.length === 1 ? "" : "s") + " for this session that the witness's answer left out");
  return { ok: true, tree_size: size, root_hash: proofs.head.root_hash, logged: statements.length, indexes: statements.map(s => bySig.get(s.sig).leaf_index) };
}

// Two tree heads the witness signed, kept by two different parties. Either the smaller is a prefix
// of the larger (the consistency proof shows it) or the witness showed them different histories.
export function checkHeads(a, b, path, c, opts = {}) {
  for (const [n, h] of [["first", a], ["second", b]]) { const r = checkHead(h, c, opts); if (!r.ok) return no("HEAD", "the " + n + " tree head: " + r.why); }
  if (a.origin !== b.origin) return no("HEAD", "the two tree heads name different logs");
  const [x, y] = a.tree_size <= b.tree_size ? [a, b] : [b, a];
  if (x.tree_size === y.tree_size) return x.root_hash === y.root_hash ? { ok: true, same: true, first: x.tree_size, second: y.tree_size }
    : no("SPLIT", "the witness signed two different trees of the same size " + x.tree_size + "; both heads verify, so this is proof it showed two histories");
  if (!M.verifyConsistency(c.sha256, x.tree_size, y.tree_size, M.fromHex(x.root_hash), M.fromHex(y.root_hash), (path || []).map(M.fromHex)))
    return no("SPLIT", "the tree at size " + y.tree_size + " does not extend the tree at size " + x.tree_size + "; both heads are signed by the witness");
  return { ok: true, first: x.tree_size, second: y.tree_size };
}

// A monitor: rebuild the whole tree from every entry and compare with the head, then compare what
// the log holds for one session with what the witness's memory answered.
export function monitor(entries, head, c, opts = {}) {
  const h = checkHead(head, c, opts);
  if (!h.ok) return h;
  if (entries.length !== head.tree_size || entries.some((e, i) => e.index !== i)) return no("ENTRIES", "expected " + head.tree_size + " entries in order, got " + entries.length);
  const leaves = entries.map(e => M.leafHash(c.sha256, entryBytes(e)));
  const root = M.toHex(M.rootOf(c.sha256, leaves, 0, leaves.length, new Map()));
  if (root !== head.root_hash) return no("ROOT", "the entries do not rebuild the signed tree head");
  const out = { ok: true, tree_size: head.tree_size, kinds: {} };
  for (const e of entries) out.kinds[e.kind] = (out.kinds[e.kind] || 0) + 1;
  if (opts.recorderKey && opts.sessionFp && opts.memory) {
    const inLog = entries.filter(e => e.kind === "statement").map(e => JSON.parse(e.entry)).filter(s => s.recorder_key === opts.recorderKey && s.session_fp === opts.sessionFp);
    const mem = new Set(opts.memory.map(s => s.sig)), logged = new Set(inLog.map(s => s.sig));
    const hidden = inLog.filter(s => !mem.has(s.sig)), unlogged = opts.memory.filter(s => !logged.has(s.sig));
    if (hidden.length) return no("HIDDEN", "the log holds " + hidden.length + " statement" + (hidden.length === 1 ? "" : "s") + " for this session that the witness's memory did not return (line " + hidden.map(s => s.count).join(", ") + ")");
    if (unlogged.length) return no("UNLOGGED", unlogged.length + " remembered statement" + (unlogged.length === 1 ? " is" : "s are") + " not in the log");
    out.session = inLog.length;
  }
  return out;
}

// RFC 9942 COSE Receipt (inclusion). entry: the logged bytes. Returns the root the receipt signs.
export function checkReceipt(receipt, entry, c, opts = {}) {
  let r; try { r = C.readReceipt(receipt); } catch (e) { return no("RECEIPT", e.message); }
  if (r.proofType !== C.P_INCLUSION) return no("RECEIPT", "this is not an inclusion receipt");
  const kid = new TextDecoder().decode(r.kid || new Uint8Array(0));
  if (opts.witnessPin && kid !== opts.witnessPin) return no("RECEIPT", "the receipt is signed by another key than the pinned witness");
  const [size, index, path] = r.proof;
  if (!Number.isInteger(size) || !Number.isInteger(index) || !Array.isArray(path) || !(index < size)) return no("RECEIPT", "the inclusion proof is malformed");
  const leaf = M.leafHash(c.sha256, entry);
  let fn = index, sn = size - 1, x = leaf;
  for (const p of path) {
    if (sn === 0) return no("RECEIPT", "the inclusion path is too long");
    if ((fn & 1) || fn === sn) { x = M.nodeHash(c.sha256, p, x); if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    else x = M.nodeHash(c.sha256, x, p);
    fn >>= 1; sn >>= 1;
  }
  if (sn !== 0) return no("RECEIPT", "the inclusion path is too short");
  if (!c.verifyBytes(kid, r.sigStructureFor(x), r.signature)) return no("RECEIPT", "the receipt's signature does not verify over the root this entry proves to");
  if (opts.head && (opts.head.tree_size !== size || opts.head.root_hash !== M.toHex(x))) return no("RECEIPT", "the receipt's tree does not match the saved tree head");
  return { ok: true, tree_size: size, leaf_index: index, root_hash: M.toHex(x), iss: r.iss, sub: r.sub };
}

// c2sp.org/tlog-checkpoint with c2sp.org/signed-note and c2sp.org/tlog-cosignature lines.
//   opts: { origin, logKey, cosigners: [{ name, key }], quorum }
export function checkCheckpoint(text, c, opts = {}) {
  const i = String(text).indexOf("\n\n");
  if (i < 0) return no("CHECKPOINT", "not a signed note");
  const body = text.slice(0, i + 1), sigs = text.slice(i + 2).split("\n").filter(Boolean);
  const [origin, sizeS, rootB64] = body.split("\n");
  if (opts.origin && origin !== opts.origin) return no("CHECKPOINT", "the checkpoint names another log");
  const size = Number(sizeS); if (!/^\d+$/.test(sizeS || "")) return no("CHECKPOINT", "bad tree size");
  const keyId = (name, type, key) => c.sha256(new Uint8Array([...te.encode(name), 0x0a, type, ...fromB64(key)])).slice(0, 4);
  let logOk = false; const cosigned = [];
  for (const line of sigs) {
    const m = /^\u2014 (\S+) ([A-Za-z0-9+/=]+)$/.exec(line); if (!m) continue;
    const raw = fromB64(m[2]);
    if (m[1] === origin && opts.logKey && raw.length === 68 && sameBytes(raw.slice(0, 4), keyId(origin, 1, opts.logKey)))
      logOk = logOk || c.verifyBytes(opts.logKey, te.encode(body), raw.slice(4));
    for (const w of opts.cosigners || []) {
      if (m[1] !== w.name || raw.length !== 76 || !sameBytes(raw.slice(0, 4), keyId(w.name, 4, w.key))) continue;
      let t = 0; for (let k = 4; k < 12; k++) t = t * 256 + raw[k];
      if (c.verifyBytes(w.key, te.encode("cosignature/v1\ntime " + t + "\n" + body), raw.slice(12))) cosigned.push({ name: w.name, time: new Date(t * 1000).toISOString() });
    }
  }
  if (!logOk) return no("CHECKPOINT", "the log's own signature on the checkpoint does not verify");
  const root = Array.from(fromB64(rootB64), b => b.toString(16).padStart(2, "0")).join("");
  if ((opts.quorum || 0) > cosigned.length) return no("COSIGNED", "the checkpoint carries " + cosigned.length + " of the " + opts.quorum + " outside cosignatures required", { tree_size: size, cosigned });
  return { ok: true, origin, tree_size: size, root_hash: root, cosigned };
}
export { toB64 };
