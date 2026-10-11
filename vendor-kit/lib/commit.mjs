// Commitments a vendor puts in a signed delivery record, so a later calculation can be proven to use exactly
// the delivered values without anyone else seeing them. Matches passport/circuits/spread.circom:
//   C = Poseidon3( Poseidon8(id[0..7]), Poseidon8(v[0..7]), salt )
// id: the bond identifier as a base-36 number (9 characters 0-9, A-Z); v: the value in integer units
// (yields in thousandths of a percent, so 5.412% is 5412); salt: 248 random bits, returned only to the customer.
import crypto from "node:crypto";
import { poseidon3, poseidon8 } from "./poseidon.mjs";

export const SCHEME = "hive.poseidon-commit/1";
export const N = 8;
export const idToField = s => {
  if (!/^[0-9A-Z]{9}$/.test(String(s))) throw new Error("identifier must be 9 characters, 0-9 or A-Z: " + s);
  return [...String(s)].reduce((a, ch) => a * 36n + BigInt(parseInt(ch, 36)), 0n);
};
export const toUnits = (x, scale) => {
  const u = Math.round(Number(x) * scale);
  if (!Number.isFinite(Number(x)) || Math.abs(Number(x) * scale - u) > 1e-6 || u < 0 || u >= 2 ** 20) throw new Error("value " + x + " is not a whole number of 1/" + scale + " units in range");
  return BigInt(u);
};
export const newSalt = () => BigInt("0x" + crypto.randomBytes(31).toString("hex"));
export function commitVector(ids, values, salt) {
  if (ids.length !== N || values.length !== N) throw new Error("commitments cover exactly " + N + " rows");
  return poseidon3([poseidon8(ids.map(idToField)), poseidon8(values.map(BigInt)), BigInt(salt)]).toString();
}
// From a delivered body and a profile { rows, id, value, scale }: the integer values and a commitment.
export function commitRows(body, p, salt = newSalt()) {
  const rows = body && body[p.rows];
  if (!Array.isArray(rows) || rows.length !== N) throw new Error("expected " + N + " rows in " + p.rows);
  const ids = rows.map(r => String(r[p.id])), values = rows.map(r => toUnits(r[p.value], p.scale));
  return { ids, values, salt, commitment: { scheme: SCHEME, rows: p.rows, id: p.id, value: p.value, scale: p.scale, n: N, value_commitment: commitVector(ids, values, salt) } };
}
// The salt travels to the customer as letters only, like the delivery id, so it never adds figures to a result
// that a recorder or a figure check would read as data.
export const saltToText = s => { let x = BigInt(s), o = ""; do { o = String.fromCharCode(97 + Number(x % 26n)) + o; x /= 26n; } while (x > 0n); return "sl-" + o; };
export const textToSalt = t => { if (!/^sl-[a-z]+$/.test(t)) throw new Error("not a salt"); return [...t.slice(3)].reduce((a, ch) => a * 26n + BigInt(ch.charCodeAt(0) - 97), 0n); };
