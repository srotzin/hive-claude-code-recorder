// Shared key checks. Three holders run as separate processes with their own identity keys, state and data.
// Signing and registration go to a local witness (HIVE_TEST_WITNESS, default http://localhost:8799) and a
// second witness with the same key and a different history (HIVE_TEST_FORK, default http://localhost:8798).
// Usage-inventory views read the live witness's memory (HIVE_TEST_MEMORY), read only.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadSharedKeyNode } from "../shared-key/shared-key.mjs";
import { ceremony, cosign, statement, signWith, post, NAME } from "../shared-key/coordinator.mjs";
import { inventoryOf } from "../shared-key/views.mjs";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const W = process.env.HIVE_TEST_WITNESS || "http://localhost:8799", FORK = process.env.HIVE_TEST_FORK || "http://localhost:8798";
const MEM = process.env.HIVE_TEST_MEMORY || "https://witness.thehiveryiq.com", MEM_KEY = "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE";
const EX = path.join(ROOT, "examples/claude-code-gateway");
let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { (cond ? pass++ : fail++); console.log((cond ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); };
const refused = async (name, fn, re) => { try { await fn(); ok(name, false, "was not refused"); } catch (e) { ok(name, re.test(e.message), e.message); } };
const sk = await loadSharedKeyNode();
const getJ = async u => (await fetch(u)).json();
const logKey = (await getJ(W + "/v1/witness/key")).witness_key, origin = "localhost/log";
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hive-sk-"));
const procs = [];
process.on("exit", () => procs.forEach(p => { try { p.kill(); } catch {} }));

async function grow(base, n) { // add n witnessed statements to a witness log
  const { privateKey } = crypto.generateKeyPairSync("ed25519"), rk = crypto.createPublicKey(privateKey).export({ format: "jwk" }).x, sfp = crypto.randomBytes(32).toString("hex");
  for (let i = 1; i <= n; i++) {
    const req = { count: i, head: crypto.randomBytes(32).toString("hex"), recorder_key: rk, session_fp: sfp };
    await fetch(base + "/v1/witness", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...req, req_sig: crypto.sign(null, Buffer.from(canon(req)), privateKey).toString("base64url") }) });
  }
}
function trio(tag, port0) {
  const roles = [["vendor", "ice-standin.thehiveryiq.com/shared-key"], ["firm", "firm-standin.thehiveryiq.com/shared-key"], ["hive", "hive.thehiveryiq.com/shared-key"]];
  const d = path.join(tmp, tag); fs.mkdirSync(d);
  const peers = {}, cfgs = [];
  roles.forEach(([role, name], i) => {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    fs.writeFileSync(path.join(d, role + ".pem"), privateKey.export({ type: "pkcs8", format: "pem" }));
    peers[i + 1] = { name, identity_key: crypto.createPublicKey(privateKey).export({ format: "jwk" }).x };
    cfgs.push({ id: i + 1, name, role, identity_key: role + ".pem", dir: role + "-state", port: port0 + i, peers: "peers.json", log: W, log_key: logKey, origin, memory: MEM, witness_key: MEM_KEY,
      data: { match: path.join(EX, "copies/match.market-data.json"), vendor_log: path.join(EX, "vendor/market-data.deliveries.jsonl"), own_delivery_log: path.join(EX, "vendor/market-data.deliveries.jsonl"),
        own_vendor_key: "fzRLBYluTLJaa2DW8T11AaBbIH2OUE8hk8akjX9BNgI", own_recorder_key: "IyC-i5liFGbjfJm1zMESe73_tt1vk4BNotjZA94umDY", vendor_key_pin: "fzRLBYluTLJaa2DW8T11AaBbIH2OUE8hk8akjX9BNgI",
        own_sessions: [path.join(EX, "session-1.jsonl"), path.join(EX, "session-2.jsonl")] } });
  });
  fs.writeFileSync(path.join(d, "peers.json"), JSON.stringify(peers, null, 1));
  cfgs.forEach(c => fs.writeFileSync(path.join(d, c.role + ".json"), JSON.stringify(c, null, 1)));
  return { d, cfgs, urls: cfgs.map(c => "http://127.0.0.1:" + c.port) };
}
async function start(t, i, pass = "a passphrase only this party knows " + i) {
  const p = spawn(process.execPath, [path.join(ROOT, "shared-key/party.mjs"), "--config", path.join(t.d, t.cfgs[i].role + ".json")], { env: { ...process.env, HIVE_PARTY_PASSPHRASE: pass }, stdio: ["ignore", "pipe", "pipe"] });
  procs.push(p); t.procs = t.procs || []; t.procs[i] = p;
  let err = ""; p.stderr.on("data", x => err += x);
  for (let k = 0; k < 50; k++) { await new Promise(r => setTimeout(r, 100)); try { await fetch(t.urls[i] + "/public"); return p; } catch {} if (p.exitCode !== null) throw new Error(err.split("\n").find(l => /Error/.test(l)) || err); }
  throw new Error("party did not start");
}
const stop = async (t, i) => { t.procs[i].kill(); await new Promise(r => t.procs[i].once("exit", r)); };

// ---------------------------------------------------------------- key creation
const A = trio("a", 8901);
for (let i = 0; i < 3; i++) await start(A, i);
const rec = await ceremony(A.urls, "ck-test-" + crypto.randomBytes(4).toString("hex"));
const pubs = await Promise.all(A.urls.map(u => getJ(u + "/public")));
ok("three holders end with one shared key and the same public record", new Set(pubs.map(p => p.group_key + canon(p.ceremony))).size === 1, rec.group_key);
let cc = sk.call("check_ceremony", { round1: Object.fromEntries(rec.parties.map(p => [p.id, p.round1_package])), public_key_package: rec.public_key_package });
ok("anyone can recheck the ceremony record: each holder proved its commitment, and the key follows from them", cc.ok && cc.min_signers === 2 && cc.parties === 3 && cc.group_key === rec.group_key);
ok("the record names the exact signer code each holder ran", pubs.every(p => p.signer_code_wasm_sha256 === rec.signer_code_wasm_sha256) && rec.signer_code_wasm_sha256 === crypto.createHash("sha256").update(fs.readFileSync(path.join(ROOT, "shared-key/dist/hive_shared_key.wasm"))).digest("hex"));
const sealed = fs.readFileSync(path.join(A.d, "vendor-state/share.sealed.json"), "utf8");
ok("each share is stored encrypted under its holder's passphrase", !/key_package|signing_share/.test(sealed) && JSON.parse(sealed).aead === "AES-256-GCM");
const badPkp = (() => { const b = Buffer.from(rec.public_key_package, "hex"); b[b.length - 40] ^= 1; return b.toString("hex"); })();
await refused("a published record with one holder's public share changed fails the recheck", () => sk.call("check_ceremony", { round1: Object.fromEntries(rec.parties.map(p => [p.id, p.round1_package])), public_key_package: badPkp }), /follow|Malformed|Invalid|Deserial|point/i);
const r1bad = Object.fromEntries(rec.parties.map(p => [p.id, p.round1_package])); { const b = Buffer.from(r1bad[2], "hex"); b[b.length - 5] ^= 1; r1bad[2] = b.toString("hex"); }
await refused("a published record with one holder's commitment proof changed fails the recheck", () => sk.call("check_ceremony", { round1: r1bad, public_key_package: rec.public_key_package }), /prove|Invalid|Malformed|follow/i);

// key-creation attacks by a dishonest coordinator, on a fresh set of holders
const B = trio("b", 8911);
for (let i = 0; i < 3; i++) await start(B, i);
const ids = [1, 2, 3], cid = "ck-attack-" + crypto.randomBytes(4).toString("hex");
const anns = await Promise.all(B.urls.map(u => post(u + "/dkg/start", { ceremony_id: cid, min: 2, max: 3, parties: ids })));
const forged = anns.map(a => a.id === 2 ? { ...a, round1_package: anns[0].round1_package } : a);
await refused("key creation: a holder's announcement swapped by the coordinator is refused", () => post(B.urls[0] + "/dkg/round2", { announcements: forged }), /not signed by its identity key/);
const own = anns.map(a => a.id === 1 ? { ...a, transport_key: anns[1].transport_key } : a);
await refused("key creation: a holder's own announcement changed by the coordinator is refused", () => post(B.urls[0] + "/dkg/round2", { announcements: own }), /identity key|changed this party/);
await refused("key creation: a 1-of-3 key is refused", () => post(B.urls[1] + "/dkg/start", { ceremony_id: cid + "x", min: 1, max: 3, parties: ids }), /2-of-3/);
const r2 = await Promise.all(B.urls.map(u => post(u + "/dkg/round2", { announcements: anns })));
const forMe = id => Object.fromEntries(r2.filter(x => x.from !== id).map(x => [x.from, x.to[id]]));
const swapped = { ...forMe(1), 2: r2.find(x => x.from === 3).to[1] };
await refused("key creation: a secret message relabelled as coming from another holder is refused", () => post(B.urls[0] + "/dkg/finish", { round2: swapped }), /was not encrypted by it to this party/);
const misdirected = { ...forMe(1), 2: r2.find(x => x.from === 2).to[3] };
await refused("key creation: a secret message meant for a different holder is refused", () => post(B.urls[0] + "/dkg/finish", { round2: misdirected }), /was not encrypted by it to this party/);
const finB = await Promise.all(B.urls.map((u, i) => post(u + "/dkg/finish", { round2: forMe(i + 1) })));
ok("after refusing those, the same holders still complete an honest ceremony", new Set(finB.map(f => f.group_key)).size === 1);
await refused("key creation runs once: a holder with a share refuses to start again", () => post(B.urls[0] + "/dkg/start", { ceremony_id: cid + "y", min: 2, max: 3, parties: ids }), /already holds a share/);

// ---------------------------------------------------------------- checkpoints
await grow(W, 2);
let t1 = await cosign(sk, [A.urls[0], A.urls[1]], W, origin, logKey, true);
const gpub = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: rec.group_key }, format: "jwk" });
ok("ICE and the firm cosign the log checkpoint; the witness accepts it as an ordinary Ed25519 cosignature", t1.posted.status === 200 && crypto.verify(null, Buffer.from(t1.message, "hex"), gpub, Buffer.from(t1.signature, "hex")), "size " + t1.tree_size);
const cpText = await (await fetch(W + "/v1/witness/log/checkpoint")).text();
ok("the checkpoint the witness serves now carries the shared key's line", cpText.includes("\u2014 " + NAME + " "));
await grow(W, 3);
const t2 = await cosign(sk, [A.urls[1], A.urls[2]], W, origin, logKey, true);
await grow(W, 1);
const t3 = await cosign(sk, [A.urls[0], A.urls[2]], W, origin, logKey, true);
ok("any two of the three can sign: firm and Hive, then ICE and Hive, each over a larger tree", t2.posted.status === 200 && t3.posted.status === 200 && t3.tree_size > t2.tree_size && t2.tree_size > t1.tree_size, `${t1.tree_size} -> ${t2.tree_size} -> ${t3.tree_size}`);
const stA = JSON.parse(fs.readFileSync(path.join(A.d, "vendor-state/checkpoint-state.json"), "utf8"));
ok("ICE's holder checked a consistency proof from the tree it last signed before signing the larger one", stA.signed.at(-1).from_size === t1.tree_size && stA.signed.at(-1).proof_hashes > 0, JSON.stringify(stA.signed.at(-1)));
for (const t of [t1, t2, t3]) for (const id of t.signers) sk.call("verify_share", { id, public_key_package: t.public_key_package, share: t.shares[id], signing_package: t.signing_package });
ok("from each published transcript, anyone can check which two holders took part", true, [t1, t2, t3].map(t => t.signers.join("+")).join(", "));

await refused("ICE alone cannot sign", () => cosign(sk, [A.urls[0]], W, origin, logKey, false), /not enough parties/);
await stop(A, 1); await stop(A, 2);
await refused("with the firm's and Hive's holders stopped, nothing gets signed", () => cosign(sk, [A.urls[0], A.urls[1]], W, origin, logKey, false), /fetch failed|ECONNREFUSED/);
await start(A, 1); await start(A, 2);
await grow(W, 1);
const t4 = await cosign(sk, [A.urls[1], A.urls[2]], W, origin, logKey, true);
ok("restarted holders reload their sealed shares and their last signed tree, and sign again", t4.posted.status === 200 && JSON.parse(fs.readFileSync(path.join(A.d, "firm-state/checkpoint-state.json"), "utf8")).signed.at(-1).from_size === t2.tree_size);

const old = t1.checkpoint, oldTime = Math.floor(Date.now() / 1000);
await refused("a smaller, older tree is refused by a holder that already signed a larger one", () => signWith(sk, [A.urls[1], A.urls[2]], sk.call("checkpoint_message", { checkpoint: old, origin, log_key: logKey, time: oldTime, now: oldTime, state: null, proof: [] }).message,
  (p, session, signing_package) => post(p + "/sign/checkpoint", { session, signing_package, checkpoint: old, time: oldTime })), /went back/);
{ const need = Number((await (await fetch(W + "/v1/witness/log/checkpoint")).text()).split("\n")[1]) + 3 - Number((await (await fetch(FORK + "/v1/witness/log/checkpoint")).text()).split("\n")[1]); if (need > 0) await grow(FORK, need); }
const forkCp = await (await fetch(FORK + "/v1/witness/log/checkpoint")).text(), ft = Math.floor(Date.now() / 1000);
await refused("a second history from the same witness key (a split view) is refused", () => signWith(sk, [A.urls[0], A.urls[2]], sk.call("checkpoint_message", { checkpoint: forkCp, origin, log_key: logKey, time: ft, now: ft, state: null, proof: [] }).message,
  (p, session, signing_package) => post(p + "/sign/checkpoint", { session, signing_package, checkpoint: forkCp, time: ft })), /does not extend the tree/);
const cur = await (await fetch(W + "/v1/witness/log/checkpoint")).text();
const tampered = cur.replace(/\n(\d+)\n/, (m, n) => "\n" + (Number(n) + 1) + "\n");
await refused("a checkpoint the log did not sign is refused", () => signWith(sk, [A.urls[0], A.urls[1]], Buffer.from("x").toString("hex"),
  (p, session, signing_package) => post(p + "/sign/checkpoint", { session, signing_package, checkpoint: tampered, time: ft })), /log's own signature/);
await refused("a coordinator asking holders to sign some other message under a real checkpoint is refused", () => signWith(sk, [A.urls[0], A.urls[1]], Buffer.from("cosignature/v1\ntime 1\nsomething else\n").toString("hex"),
  (p, session, signing_package) => post(p + "/sign/checkpoint", { session, signing_package, checkpoint: cur, time: ft })), /something other than this checkpoint/);
const skew = ft + 3600;
await refused("a signing time an hour off the holder's clock is refused", () => signWith(sk, [A.urls[0], A.urls[1]], sk.call("checkpoint_message", { checkpoint: cur, origin, log_key: logKey, time: skew, now: skew, state: null, proof: [] }).message,
  (p, session, signing_package) => post(p + "/sign/checkpoint", { session, signing_package, checkpoint: cur, time: skew })), /10 minutes/);
{
  const s = "s-reuse-" + crypto.randomBytes(6).toString("hex");
  const c1 = await post(A.urls[0] + "/commit", { session: s }), c2 = await post(A.urls[1] + "/commit", { session: s });
  const msg = sk.call("checkpoint_message", { checkpoint: cur, origin, log_key: logKey, time: ft, now: ft, state: null, proof: [] }).message;
  const { signing_package } = sk.call("signing_package", { commitments: { 1: c1.commitments, 2: c2.commitments }, message: msg });
  await post(A.urls[0] + "/sign/checkpoint", { session: s, signing_package, checkpoint: cur, time: ft });
  await refused("a holder never signs twice with the same one-time values", () => post(A.urls[0] + "/sign/checkpoint", { session: s, signing_package, checkpoint: cur, time: ft }), /already used/);
  await refused("a holder refuses to reopen a used signing session", () => post(A.urls[0] + "/commit", { session: s }), /not new/);
}
{
  const t = await cosign(sk, [A.urls[0], A.urls[1]], W, origin, logKey, false);
  const bad = { ...t.shares, 1: (() => { const b = Buffer.from(t.shares[1], "hex"); b[3] ^= 1; return b.toString("hex"); })() };
  await refused("a forged share is caught and its holder named", () => sk.call("aggregate", { signing_package: t.signing_package, shares: bad, public_key_package: t.public_key_package }), /participant 1/);
}

// ---------------------------------------------------------------- statements
const cer = await statement(sk, [A.urls[0], A.urls[2]], rec, W, true);
const decoded = C.decode(cer.signed_statement), [prot, , payload, sig] = decoded.value || decoded;
const tbs = C.encode(["Signature1", prot, new Uint8Array(0), payload]);
ok("the key's first statement is its own ceremony record, a SCITT Signed Statement registered with a receipt", !!cer.receipt && crypto.verify(null, Buffer.from(tbs), gpub, Buffer.from(sig)), "leaf " + C.readReceipt(cer.receipt).proof[1]);
await refused("a ceremony record with one field changed is refused by every holder", () => statement(sk, [A.urls[0], A.urls[1]], { ...rec, min_signers: 1 }, W, false), /differs from what this party computed/);
await refused("a statement of a kind the key does not sign is refused", () => statement(sk, [A.urls[0], A.urls[1]], { kind: "hive.anything/1" }, W, false), /does not sign statements of kind/);

const m = JSON.parse(fs.readFileSync(path.join(EX, "copies/match.market-data.json"), "utf8"));
const vlog = fs.readFileSync(path.join(EX, "vendor/market-data.deliveries.jsonl"), "utf8").split("\n").filter(Boolean).map(JSON.parse);
const inv = inventoryOf(m, vlog);
const i1 = await statement(sk, [A.urls[0], A.urls[1]], inv, W, true);
ok("usage inventory: ICE's holder checked its own delivery log and the firm's holder its own records, and both signed", !!i1.receipt, `${inv.totals.deliveries} deliveries, ${inv.totals.matched} matched, ${inv.totals.delivered_no_record} with no record`);
const i2 = await statement(sk, [A.urls[1], A.urls[2]], inv, W, true);
ok("usage inventory: Hive's holder checked it against the witness's memory and signed with the firm", !!i2.receipt);
await refused("an inventory with one fewer delivery is refused", () => statement(sk, [A.urls[0], A.urls[2]], { ...inv, totals: { ...inv.totals, deliveries: 3 } }, W, false), /differs from what this party computed/);
await refused("an inventory that drops the delivery the firm has no record of is refused", () => statement(sk, [A.urls[1], A.urls[2]], { ...inv, deliveries: inv.deliveries.filter(d => d.status === "matched") }, W, false), /differs/);
await refused("an inventory for a period no holder has a signed match for is refused", () => statement(sk, [A.urls[0], A.urls[1]], { ...inv, period: { from: inv.period.from, to: "2026-12-31T00:00:00.000Z" } }, W, false), /no signed match/);
{ // the vendor's own log changes after the match: ICE's holder refuses; the firm and Hive still agree with each other
  const vfile = path.join(A.d, "vendor-own.jsonl"), lines = vlog.map(x => ({ ...x }));
  lines[3].datasets = ["futures.wti.eod"]; fs.writeFileSync(vfile, lines.map(x => JSON.stringify(x)).join("\n") + "\n");
  const cfg = JSON.parse(fs.readFileSync(path.join(A.d, "vendor.json"), "utf8")); cfg.data.own_delivery_log = vfile; fs.writeFileSync(path.join(A.d, "vendor.json"), JSON.stringify(cfg));
  await stop(A, 0); await start(A, 0);
  await refused("if ICE's own log no longer matches what it signed, ICE's holder refuses the inventory", () => statement(sk, [A.urls[0], A.urls[1]], inv, W, false), /own delivery log fails|not this vendor's own log/);
}
await stop(A, 0);
await refused("a holder will not start with the wrong passphrase", () => start(A, 0, "the wrong passphrase entirely"), /Unsupported state|auth|decrypt/i);

console.log(`\n${pass} passed, ${fail} failed`);
fs.writeFileSync(path.join(tmp, "transcripts.json"), JSON.stringify({ ceremony: rec, checkpoints: [t1, t2, t3, t4], inventory: i1.transcript }, null, 1));
process.exit(fail ? 1 : 0);
