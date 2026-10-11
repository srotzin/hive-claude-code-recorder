// What each holder of the shared key computes from its own records before it lends its share to a statement.
// The coordinator sends a statement; a party signs only if the statement is exactly what it computes here.
//
//   hive.shared-key-ceremony/1    the record of how this key was made, as this party saw it
//   hive.usage-inventory/1        one vendor's deliveries to one customer in one period, and how they matched
//   hive.approved-calculation/1   a calculation both sides agreed to (passport/), pinned by its circuit and key
//
// Usage inventory, by role. Each party starts from the same signed delivery match and vendor log, and checks
// them against what it alone holds:
//   vendor (ICE)  its own delivery log, byte for byte, and its own signature on the match
//   firm          its own recorder's full session records (checkMatch, with the witness's memory)
//   hive          the witness's memory: every session it saw in the period, and the vendor log's witnessed head
import fs from "node:fs";
import crypto from "node:crypto";
import { canon, checkDeliveries, checkMatch, matchBody } from "../plugins/hive-recorder/scripts/core.mjs";

const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const c = {
  sha256hex: sha,
  verify: (k, msg, sig) => { try { return crypto.verify(null, Buffer.from(msg), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k }, format: "jwk" }), Buffer.from(sig, "base64url")); } catch { return false; } },
};
const jl = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(JSON.parse);
const refuse = why => { throw Object.assign(new Error("refused: " + why), { refused: true }); };

// The inventory is a pure function of the signed match and the vendor log, so all three compute the same bytes.
// The usage declaration: the same deliveries, grouped into the vendor's own fee categories. Both sides hold the same
// category map (names only; rates stay in the vendor's fee schedule), so the declaration is as deterministic as the inventory.
// A delivery that reached the customer with no agent record gets its own line, so a pull made around the agent is declared,
// not lost. Hive never sets a rate, an amount or a category: the map is the vendor's, agreed by the firm.
const USE = { "matched": ["agent_use", "Agent use, recorded on both sides"], "delivered, no record": ["outside_agent_record", "Delivered, with no agent record on the firm's side"],
  "outside the match": ["outside_match", "Delivered in the period, outside the signed match"] };
export function declarationOf(inv, cats) {
  if (!cats || cats.kind !== "hive.fee-categories/1" || cats.vendor !== inv.vendor) refuse("this party holds no fee category map for " + inv.vendor);
  const groups = new Map();
  for (const d of inv.deliveries) for (const ds of d.datasets) {
    const category = cats.datasets[ds] || "Unclassified: not in the category map";
    const [use, use_label] = USE[d.status] || ["unknown", d.status];
    const k = category + "\n" + use;
    if (!groups.has(k)) groups.set(k, { category, use, use_label, datasets: [], deliveries: 0, delivery_seqs: [], rate: "per the vendor's fee schedule", amount: null });
    const g = groups.get(k); if (!g.datasets.includes(ds)) g.datasets.push(ds); g.deliveries++; g.delivery_seqs.push(d.seq);
  }
  const lines = [...groups.values()].sort((a, b) => (a.category + a.use < b.category + b.use ? -1 : 1));
  lines.forEach(l => l.datasets.sort());
  const n = u => lines.filter(l => l.use === u).reduce((s, l) => s + l.deliveries, 0);
  return { categories_sha256: sha(canon(cats)), fee_schedule_ref: cats.fee_schedule_ref, lines,
    totals: { agent_use: n("agent_use"), outside_agent_record: n("outside_agent_record"), outside_match: n("outside_match"), unclassified: lines.filter(l => l.category.startsWith("Unclassified")).reduce((s, l) => s + l.deliveries, 0) } };
}

export function inventoryOf(m, vlog) {
  const inP = t => Date.parse(t) >= Date.parse(m.period.from) && Date.parse(t) <= Date.parse(m.period.to);
  const matched = new Set(m.matches.map(x => x.delivery_seq)), unrec = new Set(m.unrecorded.map(x => x.delivery_seq));
  const deliveries = vlog.filter(d => inP(d.t)).map(d => ({ seq: d.seq, t: d.t, tool: d.tool, datasets: d.datasets, delivery_fp: d.delivery_fp,
    status: matched.has(d.seq) ? "matched" : unrec.has(d.seq) ? "delivered, no record" : "outside the match" }));
  return { kind: "hive.usage-inventory/1", vendor: m.vendor, customer: m.customer, period: m.period, vendor_key: m.vendor_key, recorder_key: m.recorder_key,
    vendor_log: m.log, sessions: m.sessions, deliveries,
    totals: { deliveries: deliveries.length, matched: m.matches.length, delivered_no_record: m.unrecorded.length, recorded_no_delivery: m.unmatched.length },
    match_sha256: sha(canon(m)), firm_accepted_at: m.accepted ? m.accepted.accepted_at : null };
}
export function inventoryWith(m, vlog, cats) { const inv = inventoryOf(m, vlog); return cats === undefined ? inv : { ...inv, declaration: declarationOf(inv, cats) }; }

async function getJ(u) { const r = await fetch(u); if (!r.ok) refuse("the witness did not answer " + u.split("?")[0]); return r.json(); }

async function usageInventory(cfg, rel, want) {
  const d = cfg.data, m = JSON.parse(fs.readFileSync(rel(d.match), "utf8")), vlog = jl(rel(d.vendor_log));
  if (want.vendor !== m.vendor || want.customer !== m.customer || canon(want.period) !== canon(m.period)) refuse("this party has no signed match for that vendor, customer and period");
  const { sig, accepted, ...b } = m;
  if (!c.verify(m.vendor_key, canon(b), sig)) refuse("the match is not signed by the vendor key");
  if (!accepted || !c.verify(accepted.recorder_key, canon({ match_sha256: sha(canon({ ...b, sig })), accepted_at: accepted.accepted_at }), accepted.sig) || accepted.recorder_key !== m.recorder_key)
    refuse("the firm has not accepted this match");
  if (cfg.role === "vendor") {
    const own = jl(rel(d.own_delivery_log));
    if (m.vendor_key !== d.own_vendor_key) refuse("the match is signed by a key other than this vendor's");
    const ok = checkDeliveries(own, c, { vendorPin: d.own_vendor_key });
    if (!ok.ok) refuse("this vendor's own delivery log fails: " + ok.why);
    if (canon(own) !== canon(vlog)) refuse("the delivery log in the match is not this vendor's own log");
    if (canon(m.log) !== canon({ log_fp: ok.log_fp, count: ok.deliveries, head: ok.head })) refuse("the match's log head is not this vendor's");
  } else if (cfg.role === "firm") {
    if (m.recorder_key !== d.own_recorder_key) refuse("the match names a recorder key other than this firm's");
    const discs = d.own_sessions.map(f => jl(rel(f)));
    const memory = {};
    for (const L of discs) { const sfp = sha(String(L[0].session)); memory[sfp] = (await getJ(`${cfg.memory || cfg.log}/v1/witness/statements?recorder_key=${m.recorder_key}&session_fp=${sfp}`)).statements; }
    const logMemory = (await getJ(`${cfg.memory || cfg.log}/v1/witness/statements?recorder_key=${m.vendor_key}&session_fp=${m.log.log_fp}`)).statements;
    const witnessSessions = (await getJ(`${cfg.memory || cfg.log}/v1/witness/sessions?recorder_key=${m.recorder_key}&from=${m.period.from}&to=${m.period.to}`)).sessions;
    const r = checkMatch(m, discs, vlog, c, { recorderPin: d.own_recorder_key, vendorPin: d.vendor_key_pin, witnessPin: cfg.witness_key, memory, logMemory, witnessSessions });
    if (!r.ok) refuse("the match does not agree with this firm's own records: " + r.step + ", " + r.why);
  } else if (cfg.role === "hive") {
    const ws = (await getJ(`${cfg.memory || cfg.log}/v1/witness/sessions?recorder_key=${m.recorder_key}&from=${m.period.from}&to=${m.period.to}`)).sessions;
    const seen = ws.filter(w => Date.parse(w.last_at) >= Date.parse(m.period.from) && Date.parse(w.last_at) <= Date.parse(m.period.to))
      .map(w => ({ session_fp: w.session_fp, count: w.count, head: w.head })).sort((a, b) => a.session_fp < b.session_fp ? -1 : 1);
    if (canon(seen) !== canon(m.sessions)) refuse("the sessions in the match are not the sessions the witness saw in this period");
    const lm = (await getJ(`${cfg.memory || cfg.log}/v1/witness/statements?recorder_key=${m.vendor_key}&session_fp=${m.log.log_fp}`)).statements;
    const top = lm.reduce((a, s) => (!a || s.count > a.count ? s : a), null);
    if (!top || top.count !== m.log.count || top.head !== m.log.head) refuse("the vendor log head in the match is not the head the witness saw");
    const ok = checkDeliveries(vlog, c, { vendorPin: m.vendor_key, witnessPin: cfg.witness_key, memory: lm, requireMemory: true });
    if (!ok.ok) refuse("the vendor log copy fails against the witness: " + ok.why);
  } else refuse("unknown role " + cfg.role);
  // A statement that carries a declaration is signed only if this party's own category map gives the same one.
  if (want.declaration === undefined) return inventoryOf(m, vlog);
  if (!d.fee_categories) refuse("this party holds no fee category map, so it cannot sign a usage declaration");
  return inventoryWith(m, vlog, JSON.parse(fs.readFileSync(rel(d.fee_categories), "utf8")));
}

function approvedCalculation(cfg, rel, want) {
  const f = cfg.data && cfg.data.approved_calculation;
  if (!f) refuse("this party has not reviewed any calculation");
  const mine = JSON.parse(fs.readFileSync(rel(f), "utf8"));
  // Each party re-hashes the circuit source and verification key it reviewed, rather than trusting the file's own fields.
  if (sha(fs.readFileSync(rel(mine.files.circuit))) !== mine.statement.circuit_sha256) refuse("the circuit this party reviewed has changed");
  if (sha(canon(JSON.parse(fs.readFileSync(rel(mine.files.verification_key), "utf8")))) !== mine.statement.verification_key_sha256) refuse("the verification key this party reviewed has changed");
  return mine.statement;
}

export async function viewFor(cfg, rel, stmt, pub) {
  if (!stmt || typeof stmt !== "object") refuse("no statement");
  if (stmt.kind === "hive.shared-key-ceremony/1") return pub.ceremony;
  if (stmt.kind === "hive.usage-inventory/1") return usageInventory(cfg, rel, stmt);
  if (stmt.kind === "hive.approved-calculation/1") return approvedCalculation(cfg, rel, stmt);
  refuse("this party does not sign statements of kind " + stmt.kind);
}
