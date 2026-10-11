// Minimal deterministic CBOR (RFC 8949) and COSE_Sign1 (RFC 9052) for RFC 9942 COSE Receipts
// over an RFC 9162 tree (vds 1, RFC9162_SHA256). Works in Node and the browser.
// Signing and verifying are passed in, so this file has no crypto of its own.
export class Tag { constructor(tag, value) { this.tag = tag; this.value = value; } }
const te = new TextEncoder(), td = new TextDecoder();
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
function head(major, n) {
  if (n < 24) return new Uint8Array([(major << 5) | n]);
  if (n < 256) return new Uint8Array([(major << 5) | 24, n]);
  if (n < 65536) return new Uint8Array([(major << 5) | 25, n >> 8, n & 255]);
  if (n < 4294967296) return new Uint8Array([(major << 5) | 26, (n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
  const hi = Math.floor(n / 4294967296), lo = n >>> 0;
  return new Uint8Array([(major << 5) | 27, (hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255, (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255]);
}
const cmp = (a, b) => { if (a.length !== b.length) return a.length - b.length; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };
export function encode(v) {
  if (v === null || v === undefined) return new Uint8Array([0xf6]);
  if (v === true) return new Uint8Array([0xf5]);
  if (v === false) return new Uint8Array([0xf4]);
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("only integers"); return v >= 0 ? head(0, v) : head(1, -1 - v); }
  if (typeof v === "string") { const b = te.encode(v); return cat(head(3, b.length), b); }
  if (v instanceof Uint8Array) return cat(head(2, v.length), v);
  if (v instanceof Tag) return cat(head(6, v.tag), encode(v.value));
  if (Array.isArray(v)) return cat(head(4, v.length), ...v.map(encode));
  const entries = (v instanceof Map ? [...v.entries()] : Object.entries(v)).map(([k, x]) => [encode(k), encode(x)]).sort((a, b) => cmp(a[0], b[0]));
  return cat(head(5, entries.length), ...entries.flat());
}
export function decode(bytes) {
  let i = 0;
  const num = ai => {
    if (ai < 24) return ai;
    const n = ai === 24 ? 1 : ai === 25 ? 2 : ai === 26 ? 4 : ai === 27 ? 8 : -1;
    if (n < 0) throw new Error("unsupported CBOR length");
    let x = 0; for (let k = 0; k < n; k++) x = x * 256 + bytes[i++];
    return x;
  };
  const item = () => {
    if (i >= bytes.length) throw new Error("truncated CBOR");
    const b = bytes[i++], major = b >> 5, ai = b & 31;
    if (major === 7) { if (ai === 20) return false; if (ai === 21) return true; if (ai === 22 || ai === 23) return null; throw new Error("unsupported CBOR simple value"); }
    const n = num(ai);
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2) { const o = bytes.slice(i, i + n); i += n; if (o.length !== n) throw new Error("truncated CBOR"); return o; }
    if (major === 3) { const o = td.decode(bytes.slice(i, i + n)); i += n; return o; }
    if (major === 4) { const a = []; for (let k = 0; k < n; k++) a.push(item()); return a; }
    if (major === 5) { const m = new Map(); for (let k = 0; k < n; k++) { const key = item(); m.set(key, item()); } return m; }
    if (major === 6) return new Tag(n, item());
  };
  const v = item();
  if (i !== bytes.length) throw new Error("trailing bytes after CBOR item");
  return v;
}

export const ALG_EDDSA = -8, VDS_RFC9162 = 1, H_RECEIPTS = 394, H_VDS = 395, H_VDP = 396, P_INCLUSION = -1, P_CONSISTENCY = -2;
const sigStructure = (protectedBytes, payload) => encode(["Signature1", protectedBytes, new Uint8Array(0), payload]);
// Receipt: COSE_Sign1, detached payload (the RFC 9162 root at tree-size), proofs in the unprotected vdp header.
//   sign(bytes) -> Uint8Array signature (Ed25519)
export function makeReceipt({ kid, iss, sub, root, proofType, proof, sign }) {
  const prot = encode(new Map([[1, ALG_EDDSA], [4, kid], [15, new Map([[1, iss], [2, sub]])], [H_VDS, VDS_RFC9162]]));
  const unprot = new Map([[H_VDP, new Map([[proofType, [encode(proof)]]])]]);
  return encode(new Tag(18, [prot, unprot, null, sign(sigStructure(prot, root))]));
}
export const inclusionProof = (size, index, path) => [size, index, path];
export const consistencyProof = (size1, size2, path) => [size1, size2, path];
// Reads a receipt. Returns { protected, kid, iss, sub, proofType, proof, signature, sigStructureFor(root) }.
export function readReceipt(bytes) {
  const t = decode(bytes);
  if (!(t instanceof Tag) || t.tag !== 18 || !Array.isArray(t.value) || t.value.length !== 4) throw new Error("not a tagged COSE_Sign1");
  const [prot, unprot, payload, signature] = t.value;
  const ph = decode(prot);
  if (ph.get(1) !== ALG_EDDSA) throw new Error("receipt alg is not EdDSA");
  if (ph.get(H_VDS) !== VDS_RFC9162) throw new Error("receipt vds is not RFC9162_SHA256");
  if (payload !== null) throw new Error("receipt payload must be detached");
  const vdp = unprot instanceof Map ? unprot.get(H_VDP) : null;
  if (!(vdp instanceof Map)) throw new Error("receipt has no verifiable data proofs");
  const proofType = vdp.has(P_INCLUSION) ? P_INCLUSION : vdp.has(P_CONSISTENCY) ? P_CONSISTENCY : null;
  if (proofType === null) throw new Error("receipt has neither an inclusion nor a consistency proof");
  const proof = decode(vdp.get(proofType)[0]);
  const cwt = ph.get(15) instanceof Map ? ph.get(15) : new Map();
  return { kid: ph.get(4), iss: cwt.get(1), sub: cwt.get(2), proofType, proof, signature, sigStructureFor: root => sigStructure(prot, root) };
}
