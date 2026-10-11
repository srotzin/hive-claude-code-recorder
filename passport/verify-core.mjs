// Checks an answer passport: a figure an AI agent produced, with a zero-knowledge proof that it is the approved
// calculation over the exact values a vendor delivered and the weights a firm committed to beforehand.
// Runs the same in Node and in a browser, with no network: everything it needs is inside the passport,
// apart from the keys it is told to trust (pins).
//
//   pins: { group_key   the shared key held 2-of-3 by ICE, the firm and Hive (approves calculations)
//           firm_key    the firm's key (commits to its weights)
//           vendor_key  the vendor's delivery-log key
//           log_key     the witness/log key (receipts, witness statements, tree heads)
//           origin }    the log's name
//   deps: { c: { sha256(u8)->u8, sha256hex(str)->hex, verify(keyB64u, str, sigB64u)->bool, verifyBytes(keyB64u, u8, u8)->bool },
//           plonkVerify(vkey, publicSignals, proof) -> Promise<bool> }
import { canon, checkDeliveries } from "../plugins/hive-recorder/scripts/core.mjs";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";
import * as L from "../plugins/hive-recorder/scripts/log-check.mjs";

export const PASSPORT_FORMAT = "hive.answer-passport/1";
export const STEPS = ["APPROVED", "PROOF", "DELIVERED", "BOUND", "WEIGHTS", "ORDER", "ANSWER"];
const te = new TextEncoder(), td = new TextDecoder();
const fromB64 = s => Uint8Array.from(atob(String(s)), ch => ch.charCodeAt(0));

// A SCITT Signed Statement: COSE_Sign1 signed by `key`, issuer `iss` optional. Returns the decoded payload.
export function openStatement(ssB64, key, c, kind) {
  const bytes = fromB64(ssB64), t = C.decode(bytes);
  if (!(t instanceof C.Tag) || t.tag !== 18 || !Array.isArray(t.value) || t.value.length !== 4) throw new Error("not a tagged COSE_Sign1");
  const [prot, , payload, sig] = t.value, ph = C.decode(prot);
  if (ph.get(1) !== C.ALG_EDDSA) throw new Error("not EdDSA");
  if (td.decode(ph.get(4) || new Uint8Array(0)) !== key) throw new Error("signed by another key than the one pinned");
  const cwt = ph.get(15) instanceof Map ? ph.get(15) : new Map();
  if (kind && cwt.get(2) !== kind) throw new Error("the statement says it is " + cwt.get(2) + ", expected " + kind);
  if (!c.verifyBytes(key, C.encode(["Signature1", prot, new Uint8Array(0), payload]), sig)) throw new Error("the signature does not verify");
  const doc = JSON.parse(td.decode(payload));
  if (canon(doc) !== td.decode(payload)) throw new Error("the payload is not in canonical form");
  return { doc, bytes, iss: cwt.get(1) };
}

export async function verifyPassport(p, pins, deps) {
  const { c, plonkVerify } = deps, steps = [];
  const pass = (step, what) => steps.push({ step, ok: true, what });
  const fail = (step, why) => { steps.push({ step, ok: false, why }); return { ok: false, step, why, steps }; };
  if (!p || p.v !== PASSPORT_FORMAT) return fail("FORMAT", "not a " + PASSPORT_FORMAT);
  const logPin = { witnessPin: pins.log_key };

  // 1. The calculation was approved by the shared key, and the approval is in the public log.
  let calc;
  try { calc = openStatement(p.calculation.signed_statement, pins.group_key, c, "hive.approved-calculation/1").doc; }
  catch (e) { return fail("APPROVED", "the approved calculation: " + e.message); }
  const rc = L.checkReceipt(fromB64(p.calculation.receipt), fromB64(p.calculation.signed_statement), c, logPin);
  if (!rc.ok) return fail("APPROVED", "the approval's log receipt: " + rc.why);
  if (c.sha256hex(canon(p.calculation.verification_key)) !== calc.verification_key_sha256) return fail("APPROVED", "the proof's verification key is not the one the shared key approved; this is some other calculation");
  pass("APPROVED", `${calc.name}; approved by the shared key (any 2 of ICE, the firm and Hive), logged at index ${rc.leaf_index}`);

  // 2. The proof verifies under that key.
  const sig = p.proof.public_signals;
  if (!Array.isArray(sig) || sig.length !== 4 || sig.some(x => !/^\d{1,78}$/.test(String(x)))) return fail("PROOF", "the proof must carry exactly the four public values the calculation names");
  let okProof = false; try { okProof = await plonkVerify(p.calculation.verification_key, sig, p.proof.proof); } catch { okProof = false; }
  if (!okProof) return fail("PROOF", "the zero-knowledge proof does not verify for these public values");
  pass("PROOF", "PLONK proof verifies; it reveals the result and three commitments, and no yields, benchmarks or weights");

  // 3. The two deliveries are in the vendor's signed, witnessed delivery log.
  const vlog = p.inputs.vendor_log;
  const d = checkDeliveries(vlog, c, { vendorPin: pins.vendor_key, witnessPin: pins.log_key, memory: p.inputs.witness_statements, requireMemory: true });
  if (!d.ok) return fail("DELIVERED", "the vendor's delivery log: " + d.step + ", " + d.why);
  const lg = L.checkLogged(p.inputs.witness_statements, p.inputs.witness_proofs, c, { ...logPin, origin: pins.origin });
  if (!lg.ok) return fail("DELIVERED", "the witness statements in the public log: " + lg.why);
  const ev = vlog[p.inputs.evaluations_seq], bm = vlog[p.inputs.benchmarks_seq];
  for (const [name, line, spec] of [["evaluations", ev, calc.inputs.Cy], ["benchmarks", bm, calc.inputs.Cb]]) {
    if (!line) return fail("DELIVERED", "the " + name + " delivery is not in the log");
    if (line.tool !== spec.tool || canon(line.datasets) !== canon([spec.dataset]) || line.vendor !== spec.vendor) return fail("DELIVERED", "delivery " + line.seq + " is " + line.tool + " of " + line.datasets.join(", ") + "; the calculation takes " + name + " from " + spec.tool);
    const k = line.commitment || {};
    if (k.scheme !== calc.commitment_scheme || k.rows !== spec.rows || k.id !== spec.id || k.value !== spec.value || k.scale !== spec.scale || k.n !== calc.n) return fail("DELIVERED", "delivery " + line.seq + " carries no commitment to " + spec.value + " in the form the calculation needs");
  }
  if (ev.customer !== bm.customer) return fail("DELIVERED", "the two deliveries went to different customers");
  pass("DELIVERED", `deliveries ${ev.seq} and ${bm.seq} of ${vlog.length}, signed by the vendor key, each witnessed (${d.witnessed} witnessed) and logged`);

  // 4. The proof's commitments are the ones in those signed delivery lines.
  if (sig[0] !== ev.commitment.value_commitment) return fail("BOUND", "the proof used yields other than the ones in delivery " + ev.seq);
  if (sig[1] !== bm.commitment.value_commitment) return fail("BOUND", "the proof used benchmarks other than the ones in delivery " + bm.seq);
  pass("BOUND", "the yields and benchmarks inside the proof are exactly the values the vendor delivered and signed");

  // 5. The weights are the ones the firm committed to, signed by the firm and logged.
  let wdoc;
  try { wdoc = openStatement(p.inputs.weights.signed_statement, pins.firm_key, c, "hive.portfolio-commitment/1").doc; }
  catch (e) { return fail("WEIGHTS", "the firm's weights commitment: " + e.message); }
  const rw = L.checkReceipt(fromB64(p.inputs.weights.receipt), fromB64(p.inputs.weights.signed_statement), c, logPin);
  if (!rw.ok) return fail("WEIGHTS", "the weights commitment's log receipt: " + rw.why);
  if (wdoc.commitment !== sig[2] || wdoc.scheme !== calc.commitment_scheme || wdoc.value !== calc.inputs.Cw.value) return fail("WEIGHTS", "the proof used weights other than the ones the firm committed to");
  if (wdoc.customer !== ev.customer) return fail("WEIGHTS", "the weights belong to " + wdoc.customer + ", and the deliveries went to " + ev.customer);
  pass("WEIGHTS", `weights committed by ${wdoc.customer}, signed by the firm's key, logged at index ${rw.leaf_index}`);

  // 6. The weights were fixed before the data arrived: earlier in the same append-only log.
  const idx = p.inputs.witness_statements.map((st, i) => ({ count: st.count, index: lg.indexes[i] }));
  const first = idx.filter(x => x.count >= Math.min(ev.seq, bm.seq) + 1).reduce((m, x) => Math.min(m, x.index), Infinity);
  if (!(rw.leaf_index < first)) return fail("ORDER", "the weights were logged at index " + rw.leaf_index + ", after the deliveries (index " + first + "); they could have been chosen to fit the data");
  pass("ORDER", `weights logged at index ${rw.leaf_index}, before the first delivery used (index ${first})`);

  // 7. The figure in the answer is the proven result.
  const R = Number(sig[3]), shown = (R / calc.output.scale).toFixed(1);
  if (p.answer.figure !== shown) return fail("ANSWER", "the answer says " + p.answer.figure + " " + calc.output.unit + "; the proven result is " + shown);
  if (!String(p.answer.text).includes(shown)) return fail("ANSWER", "the answer text does not contain the proven figure " + shown);
  pass("ANSWER", `the answer's ${shown} ${calc.output.unit} is the proven result`);
  return { ok: true, figure: shown, unit: calc.output.unit, steps, calculation: calc.name };
}
