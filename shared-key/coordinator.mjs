#!/usr/bin/env node
// Coordinator for the shared key. It relays messages between the holders and assembles their signature
// shares. It holds no share and cannot sign; anyone can run it, and a dishonest one can only make a
// signing attempt fail, never produce a signature the holders did not each agree to.
//
//   node coordinator.mjs ceremony  --parties http://127.0.0.1:8901,...  --out ceremony.json
//   node coordinator.mjs cosign    --parties <two or more> --log https://witness.thehiveryiq.com --post --out transcript.json
//   node coordinator.mjs statement --parties <two or more> --in statement.json --log ... --register --out prefix
import fs from "node:fs";
import crypto from "node:crypto";
import { loadSharedKeyNode } from "./shared-key.mjs";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";

export const NAME = "shared.thehiveryiq.com/ice-firm-hive";
const te = new TextEncoder();
const H = u => crypto.createHash("sha256").update(u).digest();
const keyId = (name, type, raw) => H(Buffer.concat([Buffer.from(name), Buffer.from([0x0a, type]), raw])).subarray(0, 4);

export async function post(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({ error: "bad reply" }));
  if (!r.ok) throw Object.assign(new Error(j.error || r.status), { party: j.party, status: r.status });
  return j;
}
const getJ = async u => (await fetch(u)).json();

export async function ceremony(parties, ceremony_id) {
  const pubs = await Promise.all(parties.map(p => getJ(p + "/public")));
  const ids = pubs.map(p => p.id).sort((a, b) => a - b);
  const anns = await Promise.all(parties.map(p => post(p + "/dkg/start", { ceremony_id, min: 2, max: parties.length, parties: ids })));
  const r2 = await Promise.all(parties.map(p => post(p + "/dkg/round2", { announcements: anns })));
  const fin = await Promise.all(parties.map((p, i) => post(p + "/dkg/finish", { round2: Object.fromEntries(r2.filter(x => x.from !== pubs[i].id).map(x => [x.from, x.to[pubs[i].id]])) })));
  if (new Set(fin.map(f => f.group_key + f.public_key_package + f.ceremony_sha256)).size !== 1) throw new Error("the holders did not end with the same key; discard this ceremony");
  return (await getJ(parties[0] + "/public")).ceremony;
}

// Ask each listed holder to sign `message`; `ask(url, session, signing_package)` sends the holder's sign request.
export async function signWith(sk, parties, message, ask) {
  const pubs = await Promise.all(parties.map(p => getJ(p + "/public")));
  const pkp = pubs[0].public_key_package;
  if (pubs.some(p => p.public_key_package !== pkp)) throw new Error("the listed holders do not hold the same key");
  const session = "s-" + crypto.randomBytes(12).toString("hex");
  const com = await Promise.all(parties.map(p => post(p + "/commit", { session })));
  const { signing_package } = sk.call("signing_package", { commitments: Object.fromEntries(com.map(x => [x.id, x.commitments])), message });
  const shares = {};
  for (let i = 0; i < parties.length; i++) shares[pubs[i].id] = (await ask(parties[i], session, signing_package)).share;
  for (const id of Object.keys(shares)) sk.call("verify_share", { id: Number(id), public_key_package: pkp, share: shares[id], signing_package });
  const { signature } = sk.call("aggregate", { signing_package, shares, public_key_package: pkp });
  const gk = pubs[0].group_key;
  const ok = crypto.verify(null, Buffer.from(message, "hex"), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: gk }, format: "jwk" }), Buffer.from(signature, "hex"));
  if (!ok) throw new Error("the assembled signature does not verify under the shared key");
  return { v: "hive.shared-key-signature/1", group_key: gk, public_key_package: pkp, signers: Object.keys(shares).map(Number), signer_names: pubs.map(p => p.name),
    session, message, signing_package, shares, signature };
}

export async function cosign(sk, parties, log, origin, logKey, postIt) {
  const checkpoint = await (await fetch(log + "/v1/witness/log/checkpoint")).text();
  const time = Math.floor(Date.now() / 1000);
  const { message } = sk.call("checkpoint_message", { checkpoint, origin, log_key: logKey, time, now: time, state: null, proof: [] });
  const t = await signWith(sk, parties, message, (p, session, signing_package) => post(p + "/sign/checkpoint", { session, signing_package, checkpoint, time }));
  const raw = Buffer.from(t.group_key, "base64url"), tb = Buffer.alloc(8); tb.writeBigUInt64BE(BigInt(time));
  const line = `\u2014 ${NAME} ` + Buffer.concat([keyId(NAME, 4, raw), tb, Buffer.from(t.signature, "hex")]).toString("base64");
  const size = Number(checkpoint.split("\n")[1]);
  let posted = null;
  if (postIt) {
    const r = await fetch(log + "/v1/witness/log/cosignatures", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: NAME, cosigner_key: t.group_key, tree_size: size, line }) });
    posted = { status: r.status, body: await r.json() };
  }
  return { ...t, kind: "checkpoint", checkpoint, tree_size: size, time, line, posted };
}

export async function statement(sk, parties, stmt, log, register) {
  const pubs = await getJ(parties[0] + "/public");
  const m = sk.call("statement_message", { statement: stmt, group_key: pubs.group_key, iss: NAME });
  const t = await signWith(sk, parties, m.message, (p, session, signing_package) => post(p + "/sign/statement", { session, signing_package, statement: stmt, iss: NAME }));
  const prot = Buffer.from(m.protected, "hex"), payload = Buffer.from(m.payload, "hex"), sig = Buffer.from(t.signature, "hex");
  const ss = C.encode(new C.Tag(18, [new Uint8Array(prot), new Map(), new Uint8Array(payload), new Uint8Array(sig)]));
  let receipt = null, ts = null;
  if (register) {
    const r = await fetch(log + "/entries", { method: "POST", headers: { "content-type": "application/cose", accept: "application/cose" }, body: ss });
    if (r.status !== 201) throw new Error("registration refused: " + r.status + " " + await r.text());
    receipt = new Uint8Array(await r.arrayBuffer());
    ts = C.encode(new C.Tag(18, [new Uint8Array(prot), new Map([[C.H_RECEIPTS, [receipt]]]), new Uint8Array(payload), new Uint8Array(sig)]));
  }
  return { transcript: { ...t, kind: "statement", statement_kind: stmt.kind, iss: NAME }, signed_statement: ss, receipt, transparent: ts };
}

const opt = n => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : undefined; };
if (import.meta.url === "file://" + process.argv[1]) {
  const sk = await loadSharedKeyNode(), cmd = process.argv[2], parties = (opt("parties") || "").split(",").filter(Boolean);
  const log = opt("log") || "https://witness.thehiveryiq.com", origin = opt("origin") || "witness.thehiveryiq.com/log", logKey = opt("log-key") || "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE";
  try {
    if (cmd === "ceremony") { const rec = await ceremony(parties, opt("id") || "ck-" + new Date().toISOString().slice(0, 10) + "-" + crypto.randomBytes(4).toString("hex")); fs.writeFileSync(opt("out"), JSON.stringify(rec, null, 1) + "\n"); console.log(JSON.stringify({ group_key: rec.group_key, ceremony_id: rec.ceremony_id, parties: rec.parties.map(p => p.name) })); }
    else if (cmd === "cosign") { const t = await cosign(sk, parties, log, origin, logKey, process.argv.includes("--post")); if (opt("out")) fs.writeFileSync(opt("out"), JSON.stringify(t, null, 1) + "\n"); console.log(JSON.stringify({ tree_size: t.tree_size, signers: t.signer_names, posted: t.posted && t.posted.status })); }
    else if (cmd === "statement") {
      const r = await statement(sk, parties, JSON.parse(fs.readFileSync(opt("in"), "utf8")), log, process.argv.includes("--register")), out = opt("out");
      fs.writeFileSync(out + ".transcript.json", JSON.stringify(r.transcript, null, 1) + "\n"); fs.writeFileSync(out + ".signed-statement.cose", r.signed_statement);
      if (r.receipt) { fs.writeFileSync(out + ".receipt.cose", r.receipt); fs.writeFileSync(out + ".transparent.cose", r.transparent); }
      const rr = r.receipt ? C.readReceipt(r.receipt) : null;
      console.log(JSON.stringify({ kind: r.transcript.statement_kind, signers: r.transcript.signer_names, tree_size: rr && rr.proof[0], leaf_index: rr && rr.proof[1] }));
    } else console.log("usage: coordinator.mjs ceremony|cosign|statement (see the top of this file)");
  } catch (e) { console.error("failed:", e.message, e.party ? "(party " + e.party + ")" : ""); process.exit(2); }
}
