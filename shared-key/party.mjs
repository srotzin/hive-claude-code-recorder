#!/usr/bin/env node
// One holder of the shared key. ICE runs one, the firm runs one, Hive runs one, each on its own machine
// with its own identity key. The coordinator only relays messages; it never sees a share.
//
//   HIVE_PARTY_PASSPHRASE=... node party.mjs --config party.json
//
// party.json:
//   { "id": 1, "name": "ice-standin.thehiveryiq.com/shared-key", "role": "vendor" | "firm" | "hive",
//     "identity_key": "ice.pem",            Ed25519 key this party already publishes (its cosigner key)
//     "dir": "state/",                      where the encrypted share and this party's log state live
//     "port": 8901, "peers": "peers.json",  identity keys of the other two holders, agreed out of band
//     "log": "https://witness.thehiveryiq.com", "log_key": "...", "origin": "witness.thehiveryiq.com/log",
//     "data": "data/" }                     this party's own records, used by views.mjs
//
// What a party refuses, whatever the coordinator sends:
//   key creation:  an announcement not signed by a known peer, a different ceremony, threshold or party list,
//                  a key-creation message not encrypted to it by the peer it claims to come from
//   checkpoints:   anything the shared-key rules in src/lib.rs refuse (bad log signature, a tree that does not
//                  extend the one it last signed, a different tree of the same size, a time off by > 10 min)
//   statements:    a statement that differs from what views.mjs computes from this party's own records
//   nonces:        a signing session it has already used, or one it did not commit to
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import crypto from "node:crypto";
import { loadSharedKeyNode } from "./shared-key.mjs";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
import { viewFor } from "./views.mjs";

const arg = n => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : undefined; };
const cfgPath = arg("config"), cfg = JSON.parse(fs.readFileSync(cfgPath, "utf8")), base = path.dirname(path.resolve(cfgPath));
const rel = p => path.resolve(base, p);
const dir = rel(cfg.dir); fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
const peers = JSON.parse(fs.readFileSync(rel(cfg.peers), "utf8"));
const idKey = crypto.createPrivateKey(fs.readFileSync(rel(cfg.identity_key)));
const idPub = crypto.createPublicKey(idKey).export({ format: "jwk" }).x;
if (!peers[cfg.id] || peers[cfg.id].identity_key !== idPub || peers[cfg.id].name !== cfg.name) throw new Error("peers.json does not list this party's own identity key and name");
const pass = process.env.HIVE_PARTY_PASSPHRASE;
if (!pass || pass.length < 16) throw new Error("set HIVE_PARTY_PASSPHRASE (16+ characters); the share is stored encrypted under it");
const sk = await loadSharedKeyNode();
const WASM_SHA256 = crypto.createHash("sha256").update(fs.readFileSync(new URL("./dist/hive_shared_key.wasm", import.meta.url))).digest("hex");

// ---- storage: the share never leaves this process unencrypted
const F = n => path.join(dir, n);
function seal(obj) {
  const salt = crypto.randomBytes(16), k = crypto.scryptSync(pass, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 << 20 }), iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", k, iv); c.setAAD(Buffer.from(cfg.name));
  const ct = Buffer.concat([c.update(JSON.stringify(obj)), c.final()]);
  return { v: "hive.sealed-share/1", kdf: "scrypt N=32768 r=8 p=1", aead: "AES-256-GCM", salt: salt.toString("base64"), iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ct: ct.toString("base64") };
}
function unseal(s) {
  const k = crypto.scryptSync(pass, Buffer.from(s.salt, "base64"), 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 << 20 });
  const d = crypto.createDecipheriv("aes-256-gcm", k, Buffer.from(s.iv, "base64")); d.setAAD(Buffer.from(cfg.name)); d.setAuthTag(Buffer.from(s.tag, "base64"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(s.ct, "base64")), d.final()]).toString());
}
const readJ = (n, d) => { try { return JSON.parse(fs.readFileSync(F(n), "utf8")); } catch { return d; } };
const writeJ = (n, v) => { const t = F(n) + ".tmp"; fs.writeFileSync(t, JSON.stringify(v, null, 1) + "\n", { mode: 0o600 }); fs.renameSync(t, F(n)); };
let share = null; // { key_package }
const pub = () => readJ("public.json", null);
if (fs.existsSync(F("share.sealed.json"))) share = unseal(readJ("share.sealed.json"));

// ---- key creation (FROST DKG between the three holders)
let dkg = null; // in-memory only: { ceremony, r1secret, r2secret, transport, announcements }
const annBody = a => canon({ v: "hive.shared-key-dkg1/1", ceremony_id: a.ceremony_id, id: a.id, name: a.name, min: a.min, max: a.max, parties: a.parties, round1_package: a.round1_package, transport_key: a.transport_key });
const ed = k => crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k }, format: "jwk" });
const x25519Pub = k => crypto.createPublicKey({ key: { kty: "OKP", crv: "X25519", x: k }, format: "jwk" });
function boxKey(myPriv, theirPubB64u, from, to, ceremony) {
  const shared = crypto.diffieHellman({ privateKey: myPriv, publicKey: x25519Pub(theirPubB64u) });
  return Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from("hive-shared-key/dkg2"), Buffer.from(`${ceremony}|${from}->${to}`), 32));
}
function encryptTo(to, theirKey, plainHex, ceremony) {
  const k = boxKey(dkg.transport.privateKey, theirKey, cfg.id, to, ceremony), iv = crypto.randomBytes(12), aad = Buffer.from(`${ceremony}|${cfg.id}->${to}`);
  const c = crypto.createCipheriv("aes-256-gcm", k, iv); c.setAAD(aad);
  const ct = Buffer.concat([c.update(Buffer.from(plainHex, "hex")), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
}
function decryptFrom(from, theirKey, b64, ceremony) {
  const raw = Buffer.from(b64, "base64"), k = boxKey(dkg.transport.privateKey, theirKey, from, cfg.id, ceremony);
  const d = crypto.createDecipheriv("aes-256-gcm", k, raw.subarray(0, 12)); d.setAAD(Buffer.from(`${ceremony}|${from}->${cfg.id}`)); d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("hex");
}
function checkAnnouncements(anns, c) {
  const ids = Object.keys(peers).map(Number).sort((a, b) => a - b);
  if (anns.length !== ids.length) throw new Error("refused: expected an announcement from each of the " + ids.length + " holders");
  for (const a of anns) {
    const p = peers[a.id];
    if (!p || p.name !== a.name) throw new Error("refused: announcement from an unknown party " + a.id);
    if (a.ceremony_id !== c.ceremony_id || a.min !== c.min || a.max !== c.max || canon(a.parties) !== canon(c.parties)) throw new Error("refused: party " + a.id + " announced a different ceremony");
    if (!crypto.verify(null, Buffer.from(annBody(a)), ed(p.identity_key), Buffer.from(a.sig, "base64url"))) throw new Error("refused: party " + a.id + "'s announcement is not signed by its identity key");
  }
  if (canon(anns.map(a => a.id).sort((x, y) => x - y)) !== canon(ids)) throw new Error("refused: duplicate or missing holder");
}
function ceremonyRecord(c, anns, pkp, group_key) {
  return { kind: "hive.shared-key-ceremony/1", ceremony_id: c.ceremony_id, suite: "FROST(Ed25519, SHA-512), RFC 9591; key creation: FROST DKG (frost-ed25519 3.0.0)",
    min_signers: c.min, max_signers: c.max, group_key, public_key_package: pkp, signer_code_wasm_sha256: WASM_SHA256,
    parties: [...anns].sort((a, b) => a.id - b.id).map(a => ({ id: a.id, name: a.name, identity_key: peers[a.id].identity_key, round1_package: a.round1_package, transport_key: a.transport_key, announcement_sig: a.sig })) };
}

// ---- signing sessions: nonces live in memory, are used once, and are dropped on any outcome
const nonces = new Map(), used = new Set(readJ("used-sessions.json", []));
function takeNonces(session) {
  const n = nonces.get(session); nonces.delete(session);
  if (!n) throw new Error(used.has(session) ? "refused: signing session " + session + " was already used" : "refused: this party did not commit to signing session " + session);
  used.add(session); writeJ("used-sessions.json", [...used].slice(-5000));
  return n;
}
const cpState = () => readJ("checkpoint-state.json", null);

const routes = {
  "GET /public": () => ({ id: cfg.id, name: cfg.name, role: cfg.role, identity_key: idPub, signer_code_wasm_sha256: WASM_SHA256, ...(pub() || {}), checkpoint_state: cpState() }),

  "POST /dkg/start": b => {
    if (share) throw new Error("refused: this party already holds a share; key creation runs once");
    const parties = Object.keys(peers).map(Number).sort((a, b) => a - b);
    if (!/^[A-Za-z0-9._-]{8,80}$/.test(b.ceremony_id || "") || b.min !== 2 || b.max !== parties.length || canon(b.parties) !== canon(parties)) throw new Error("refused: this party joins only a 2-of-" + parties.length + " key with its known peers");
    const t = crypto.generateKeyPairSync("x25519");
    const r1 = sk.call("dkg1", { id: cfg.id, min: b.min, max: b.max });
    const a = { ceremony_id: b.ceremony_id, id: cfg.id, name: cfg.name, min: b.min, max: b.max, parties, round1_package: r1.package, transport_key: t.publicKey.export({ format: "jwk" }).x };
    a.sig = crypto.sign(null, Buffer.from(annBody(a)), idKey).toString("base64url");
    dkg = { ceremony: { ceremony_id: b.ceremony_id, min: b.min, max: b.max, parties }, r1secret: r1.secret, transport: t, own: a };
    return a;
  },
  "POST /dkg/round2": b => {
    if (!dkg) throw new Error("refused: no key creation in progress");
    checkAnnouncements(b.announcements, dkg.ceremony);
    const mine = b.announcements.find(a => a.id === cfg.id);
    if (canon(mine) !== canon(dkg.own)) throw new Error("refused: the coordinator changed this party's own announcement");
    const others = b.announcements.filter(a => a.id !== cfg.id);
    const r2 = sk.call("dkg2", { secret: dkg.r1secret, round1: Object.fromEntries(others.map(a => [a.id, a.round1_package])) });
    dkg.r2secret = r2.secret; dkg.announcements = b.announcements; delete dkg.r1secret;
    return { from: cfg.id, to: Object.fromEntries(others.map(a => [a.id, encryptTo(a.id, a.transport_key, r2.packages[a.id], dkg.ceremony.ceremony_id)])) };
  },
  "POST /dkg/finish": b => {
    if (!dkg || !dkg.r2secret) throw new Error("refused: key creation is not at its last step");
    const others = dkg.announcements.filter(a => a.id !== cfg.id);
    const r2 = {};
    for (const a of others) {
      const ct = b.round2 && b.round2[a.id];
      if (!ct) throw new Error("refused: no key-creation message from party " + a.id);
      try { r2[a.id] = decryptFrom(a.id, a.transport_key, ct, dkg.ceremony.ceremony_id); } catch { throw new Error("refused: the message said to be from party " + a.id + " was not encrypted by it to this party"); }
    }
    const r1 = Object.fromEntries(others.map(a => [a.id, a.round1_package]));
    const out = sk.call("dkg3", { secret: dkg.r2secret, round1: r1, round2: r2 });
    const all = Object.fromEntries(dkg.announcements.map(a => [a.id, a.round1_package]));
    sk.call("check_ceremony", { round1: all, public_key_package: out.public_key_package });
    const record = ceremonyRecord(dkg.ceremony, dkg.announcements, out.public_key_package, out.group_key);
    writeJ("share.sealed.json", seal({ key_package: out.key_package }));
    writeJ("public.json", { group_key: out.group_key, public_key_package: out.public_key_package, ceremony: record });
    share = { key_package: out.key_package }; dkg = null;
    return { id: cfg.id, group_key: out.group_key, public_key_package: out.public_key_package, ceremony_sha256: crypto.createHash("sha256").update(canon(record)).digest("hex") };
  },

  "POST /commit": b => {
    if (!share) throw new Error("refused: this party holds no share yet");
    if (!/^[A-Za-z0-9._-]{8,80}$/.test(b.session || "") || used.has(b.session) || nonces.has(b.session)) throw new Error("refused: signing session " + b.session + " is not new");
    const o = sk.call("commit", { key_package: share.key_package });
    nonces.set(b.session, o.nonces);
    return { id: cfg.id, session: b.session, commitments: o.commitments };
  },
  "POST /sign/checkpoint": async b => {
    const n = takeNonces(b.session);
    const now = Math.floor(Date.now() / 1000), st = cpState();
    let proof = [];
    const size = Number((/^[^\n]*\n(\d+)\n/.exec(b.checkpoint || "") || [])[1]);
    if (st && size > st.size) proof = (await (await fetch(`${cfg.log}/v1/witness/log/consistency?first=${st.size}&second=${size}`)).json()).path || [];
    const r = sk.call("sign_checkpoint", { key_package: share.key_package, nonces: n, signing_package: b.signing_package, checkpoint: b.checkpoint, origin: cfg.origin, log_key: cfg.log_key, time: b.time, now, state: st ? { size: st.size, root: st.root } : null, proof });
    writeJ("checkpoint-state.json", { ...r.state, signed: [...((st && st.signed) || []).slice(-200), { size: r.state.size, root: r.state.root, time: b.time, session: b.session, from_size: st ? st.size : 0, proof_hashes: proof.length }] });
    return { id: cfg.id, share: r.share };
  },
  "POST /sign/statement": async b => {
    const n = takeNonces(b.session);
    const p = pub(); if (!p) throw new Error("refused: this party holds no share yet");
    const mine = await viewFor(cfg, rel, b.statement, p);
    const r = sk.call("sign_statement", { key_package: share.key_package, nonces: n, signing_package: b.signing_package, statement: b.statement, my_view: mine, group_key: p.group_key, iss: b.iss });
    return { id: cfg.id, share: r.share };
  },
};

http.createServer((req, res) => {
  let raw = "";
  req.on("data", c => { raw += c; if (raw.length > 1 << 20) req.destroy(); });
  req.on("end", async () => {
    const send = (code, v) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(v, null, 1) + "\n"); };
    const h = routes[req.method + " " + req.url];
    if (!h) return send(404, { error: "not found" });
    try { send(200, await h(raw ? JSON.parse(raw) : {})); }
    catch (e) { send(e.refused || /^refused|^not enough/.test(e.message) ? 409 : 400, { error: e.message, party: cfg.id }); }
  });
}).listen(cfg.port, "127.0.0.1", () => console.log(`party ${cfg.id} (${cfg.name}) on ${cfg.port}, share ${share ? "loaded" : "not created yet"}`));
