#!/usr/bin/env node
// Cosigner for the witness's public log. ICE, the firm, or anyone else runs this with their own key.
// It cosigns a checkpoint only after it has checked that the log's new tree extends the last tree it
// cosigned (an RFC 9162 consistency proof), so once two parties cosign, the witness cannot show them
// different histories without one of them refusing.
//
// Formats: c2sp.org/tlog-checkpoint, c2sp.org/signed-note, c2sp.org/tlog-cosignature (cosignature/v1),
// c2sp.org/tlog-witness (POST /add-checkpoint) for push mode.
//
//   node cosigner.mjs keygen  --key me.pem
//   node cosigner.mjs pull    --log https://witness.thehiveryiq.com --log-key <b64url> --origin witness.thehiveryiq.com/log
//                             --name example.com/cosigner --key me.pem --state state.json [--post]
//   node cosigner.mjs serve   --log-key ... --origin ... --name ... --key ... --state ... --port 8790
import fs from "node:fs";
import http from "node:http";
import crypto from "node:crypto";
import * as M from "../plugins/hive-recorder/scripts/merkle.mjs";

const H = u => new Uint8Array(crypto.createHash("sha256").update(u).digest());
const te = new TextEncoder();
const opt = (n, d) => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : d; };
const flag = n => process.argv.includes("--" + n);
const keyId = (name, type, raw) => H(new Uint8Array([...te.encode(name), 0x0a, type, ...raw])).slice(0, 4);

export function parseCheckpoint(text) {
  const i = text.indexOf("\n\n"); if (i < 0) throw new Error("not a signed note");
  const body = text.slice(0, i + 1), lines = text.slice(i + 2).split("\n").filter(Boolean);
  const [origin, size, root] = body.split("\n");
  if (!/^\d+$/.test(size)) throw new Error("bad size");
  return { body, origin, size: Number(size), root: Buffer.from(root, "base64"), lines };
}
export function checkLogSig(cp, origin, logKeyB64u) {
  if (cp.origin !== origin) throw new Error("checkpoint names another log");
  const raw = Buffer.from(logKeyB64u, "base64url"), id = keyId(origin, 1, raw);
  const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: logKeyB64u }, format: "jwk" });
  for (const l of cp.lines) {
    const m = /^\u2014 (\S+) ([A-Za-z0-9+/=]+)$/.exec(l); if (!m || m[1] !== origin) continue;
    const s = Buffer.from(m[2], "base64");
    if (s.length === 68 && s.subarray(0, 4).equals(Buffer.from(id)) && crypto.verify(null, te.encode(cp.body), key, s.subarray(4))) return true;
  }
  throw new Error("the log's signature on the checkpoint does not verify");
}
export function cosign(cp, name, sk) {
  const pub = Buffer.from(crypto.createPublicKey(sk).export({ format: "jwk" }).x, "base64url");
  const t = Math.floor(Date.now() / 1000), tb = Buffer.alloc(8); tb.writeBigUInt64BE(BigInt(t));
  const sig = crypto.sign(null, te.encode(`cosignature/v1\ntime ${t}\n` + cp.body), sk);
  return { line: `\u2014 ${name} ` + Buffer.concat([Buffer.from(keyId(name, 4, pub)), tb, sig]).toString("base64"), time: t };
}
// The rule a cosigner enforces. state: { size, root (hex) } of the last tree it cosigned, or null.
export function advance(state, cp, proofHex) {
  if (!state || state.size === 0) return;
  if (cp.size < state.size) throw Object.assign(new Error(`the log went back from ${state.size} to ${cp.size}`), { code: 409 });
  if (cp.size === state.size) { if (Buffer.from(cp.root).toString("hex") !== state.root) throw Object.assign(new Error(`two different trees of size ${cp.size}`), { code: 409 }); return; }
  if (!M.verifyConsistency(H, state.size, cp.size, M.fromHex(state.root), new Uint8Array(cp.root), proofHex.map(M.fromHex)))
    throw Object.assign(new Error(`the tree at ${cp.size} does not extend the tree at ${state.size} this cosigner already signed`), { code: 422 });
}
const loadState = f => { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return { size: 0, root: null, cosigned: [] }; } };
const saveState = (f, s) => fs.writeFileSync(f, JSON.stringify(s, null, 1) + "\n");

async function pull() {
  const log = opt("log"), origin = opt("origin"), logKey = opt("log-key"), name = opt("name"), stateFile = opt("state");
  const sk = crypto.createPrivateKey(fs.readFileSync(opt("key")));
  const cp = parseCheckpoint(await (await fetch(log + "/v1/witness/log/checkpoint")).text());
  checkLogSig(cp, origin, logKey);
  const st = loadState(stateFile);
  let proof = [];
  if (st.size && cp.size > st.size) proof = (await (await fetch(`${log}/v1/witness/log/consistency?first=${st.size}&second=${cp.size}`)).json()).path;
  advance(st.size ? st : null, cp, proof);
  const { line, time } = cosign(cp, name, sk);
  const pub = crypto.createPublicKey(sk).export({ format: "jwk" }).x;
  let posted = null;
  if (flag("post")) {
    const r = await fetch(log + "/v1/witness/log/cosignatures", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name, cosigner_key: pub, tree_size: cp.size, line }) });
    posted = { status: r.status, body: await r.json() };
  }
  st.cosigned = [...(st.cosigned || []).slice(-50), { size: cp.size, root: Buffer.from(cp.root).toString("hex"), time, from_size: st.size || 0, proof_hashes: proof.length }];
  st.size = cp.size; st.root = Buffer.from(cp.root).toString("hex");
  saveState(stateFile, st);
  console.log(JSON.stringify({ cosigned: cp.size, root: st.root, from_size: st.cosigned.at(-1).from_size, proof_hashes: proof.length, line, posted }, null, 1));
}

// c2sp.org/tlog-witness add-checkpoint: body = "old <size>\n" + consistency hashes (base64, one per line) + "\n" + checkpoint
function serve() {
  const origin = opt("origin"), logKey = opt("log-key"), name = opt("name"), stateFile = opt("state");
  const sk = crypto.createPrivateKey(fs.readFileSync(opt("key")));
  http.createServer((req, res) => {
    if (req.method !== "POST" || req.url !== "/add-checkpoint") { res.writeHead(404); return res.end(); }
    let raw = ""; req.on("data", c => { raw += c; if (raw.length > 65536) req.destroy(); });
    req.on("end", () => {
      try {
        const i = raw.indexOf("\n\n"); const head = raw.slice(0, i).split("\n"), cpText = raw.slice(i + 2);
        const m = /^old (\d+)$/.exec(head[0] || ""); if (!m) { res.writeHead(400); return res.end("bad request\n"); }
        const old = Number(m[1]), proof = head.slice(1).map(h => Buffer.from(h, "base64").toString("hex"));
        const cp = parseCheckpoint(cpText);
        try { checkLogSig(cp, origin, logKey); } catch { res.writeHead(403); return res.end("unknown log or bad signature\n"); }
        const st = loadState(stateFile);
        if (old !== (st.size || 0)) { res.writeHead(409, { "content-type": "text/x.tlog.size" }); return res.end(String(st.size || 0) + "\n"); }
        try { advance(st.size ? st : null, cp, proof); } catch (e) { res.writeHead(e.code || 422); return res.end(e.message + "\n"); }
        const { line, time } = cosign(cp, name, sk);
        st.cosigned = [...(st.cosigned || []).slice(-50), { size: cp.size, root: Buffer.from(cp.root).toString("hex"), time, from_size: st.size || 0, proof_hashes: proof.length }];
        st.size = cp.size; st.root = Buffer.from(cp.root).toString("hex"); saveState(stateFile, st);
        res.writeHead(200, { "content-type": "text/plain; charset=utf-8" }); res.end(line + "\n");
      } catch (e) { res.writeHead(400); res.end(e.message + "\n"); }
    });
  }).listen(Number(opt("port", "8790")), () => console.log("cosigner", name, "on", opt("port", "8790")));
}

const cmd = process.argv[2];
if (cmd === "keygen") { const { privateKey } = crypto.generateKeyPairSync("ed25519"); fs.writeFileSync(opt("key"), privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 }); console.log(crypto.createPublicKey(privateKey).export({ format: "jwk" }).x); }
else if (cmd === "pull") pull().catch(e => { console.error("refused:", e.message); process.exit(2); });
else if (cmd === "serve") serve();
else if (import.meta.url === "file://" + process.argv[1]) console.log("usage: cosigner.mjs keygen|pull|serve (see the top of this file)");
