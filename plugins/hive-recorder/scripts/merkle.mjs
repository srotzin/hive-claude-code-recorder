// RFC 9162 Merkle tree: leaf and node hashing, tree heads, inclusion and consistency proofs.
// Pure functions over Uint8Array. H is a synchronous SHA-256 (Uint8Array -> Uint8Array).
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
export const toHex = u => Array.from(u, b => b.toString(16).padStart(2, "0")).join("");
export const fromHex = h => Uint8Array.from(String(h).match(/../g) || [], x => parseInt(x, 16));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const split = n => { let k = 1; while (k * 2 < n) k *= 2; return k; };

export function leafHash(H, entry) { return H(cat(new Uint8Array([0]), entry)); }
export function nodeHash(H, l, r) { return H(cat(new Uint8Array([1]), l, r)); }

// Merkle Tree Hash over leaf hashes L[lo, hi).
// memo (optional Map) keeps roots of complete subtrees, which never change once full.
export function rootOf(H, L, lo = 0, hi = L.length, memo) {
  const n = hi - lo;
  if (n === 0) return H(new Uint8Array(0));
  if (n === 1) return L[lo];
  const full = memo && (n & (n - 1)) === 0, key = full ? lo + ":" + n : "";
  if (full && memo.has(key)) return memo.get(key);
  const k = split(n);
  const r = nodeHash(H, rootOf(H, L, lo, lo + k, memo), rootOf(H, L, lo + k, hi, memo));
  if (full) memo.set(key, r);
  return r;
}
export function inclusionPath(H, L, m, lo = 0, hi = L.length, memo) {
  const n = hi - lo;
  if (n <= 1) return [];
  const k = split(n);
  return m < k ? [...inclusionPath(H, L, m, lo, lo + k, memo), rootOf(H, L, lo + k, hi, memo)]
    : [...inclusionPath(H, L, m - k, lo + k, hi, memo), rootOf(H, L, lo, lo + k, memo)];
}
function subproof(H, L, m, lo, hi, b, memo) {
  const n = hi - lo;
  if (m === n) return b ? [] : [rootOf(H, L, lo, hi, memo)];
  const k = split(n);
  return m <= k ? [...subproof(H, L, m, lo, lo + k, b, memo), rootOf(H, L, lo + k, hi, memo)]
    : [...subproof(H, L, m - k, lo + k, hi, false, memo), rootOf(H, L, lo, lo + k, memo)];
}
export function consistencyPath(H, L, m, n = L.length, memo) { return m === 0 || m === n ? [] : subproof(H, L, m, 0, n, true, memo); }

// RFC 9162 section 2.1.3.2
export function verifyInclusion(H, leaf, index, size, path, root) {
  if (!(index < size)) return false;
  let fn = index, sn = size - 1, r = leaf;
  for (const p of path) {
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) { r = nodeHash(H, p, r); if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    else r = nodeHash(H, r, p);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && eq(r, root);
}
// RFC 9162 section 2.1.4.2
export function verifyConsistency(H, size1, size2, root1, root2, path) {
  if (size1 > size2) return false;
  if (size1 === size2) return path.length === 0 && eq(root1, root2);
  if (size1 === 0) return path.length === 0;
  if (!path.length) return false;
  const p = (size1 & (size1 - 1)) === 0 ? [root1, ...path] : [...path];
  let fn = size1 - 1, sn = size2 - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = p[0], sr = p[0];
  for (const c of p.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) { fr = nodeHash(H, c, fr); sr = nodeHash(H, c, sr); if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    else sr = nodeHash(H, sr, c);
    fn >>= 1; sn >>= 1;
  }
  return eq(fr, root1) && eq(sr, root2) && sn === 0;
}
