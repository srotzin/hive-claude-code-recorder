// Public log checks against a local witness with memory (HIVE_TEST_WITNESS, default http://localhost:8799).
// Two witnesses with the same key and different histories (HIVE_TEST_FORK) stand in for a witness
// showing two parties different histories.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";
import * as L from "../plugins/hive-recorder/scripts/log-check.mjs";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";

const W = process.env.HIVE_TEST_WITNESS || "http://localhost:8799", FORK = process.env.HIVE_TEST_FORK || "http://localhost:8798";
const c = {
  sha256: u => new Uint8Array(crypto.createHash("sha256").update(u).digest()),
  verifyBytes: (pub, msg, sig) => { try { return crypto.verify(null, Buffer.from(msg), crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub }, format: "jwk" }), Buffer.from(sig)); } catch { return false; } },
};
const get = async (u, t) => { const r = await fetch(u); return t === "bytes" ? new Uint8Array(await r.arrayBuffer()) : t === "text" ? r.text() : r.json(); };
let pass = 0, fail = 0;
const ok = (name, cond, extra = "") => { (cond ? pass++ : fail++); console.log((cond ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); };

const { privateKey: rk } = crypto.generateKeyPairSync("ed25519");
const rpub = crypto.createPublicKey(rk).export({ format: "jwk" }).x;
async function witness(base, sfp, count) {
  const req = { count, head: crypto.randomBytes(32).toString("hex"), recorder_key: rpub, session_fp: sfp };
  const req_sig = crypto.sign(null, Buffer.from(canon(req)), rk).toString("base64url");
  const r = await fetch(base + "/v1/witness", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...req, req_sig }) });
  return { st: await r.json(), idx: r.headers.get("x-witness-log-index") };
}
const sfp = crypto.randomBytes(32).toString("hex");
const key = (await get(W + "/v1/witness/key")).witness_key;
const pin = { witnessPin: key };

// 1. A session of 6 lines, each witnessed and logged.
for (let i = 1; i <= 6; i++) await witness(W, sfp, i);
const headA = await get(W + "/v1/witness/log/head");
const mem = (await get(`${W}/v1/witness/statements?recorder_key=${rpub}&session_fp=${sfp}`)).statements;
const proofs = await get(`${W}/v1/witness/log/proofs?recorder_key=${rpub}&session_fp=${sfp}`);
let r = L.checkLogged(mem, proofs, c, pin);
ok("every remembered statement proves into the signed tree head", r.ok && r.logged === 6, JSON.stringify({ size: r.tree_size, idx: r.indexes }));

// 2. More history, then the two heads must be consistent.
for (let i = 7; i <= 9; i++) await witness(W, sfp, i);
const other = crypto.randomBytes(32).toString("hex"); for (let i = 1; i <= 3; i++) await witness(W, other, i);
const headB = await get(W + "/v1/witness/log/head");
const cons = await get(`${W}/v1/witness/log/consistency?first=${headA.tree_size}&second=${headB.tree_size}`);
r = L.checkHeads(headA, headB, cons.path, c, pin);
ok("the earlier head is a prefix of the later head", r.ok && r.second > r.first, `${r.first} -> ${r.second}`);

// 3. Monitor: rebuild the whole tree from its entries.
let all = []; for (let s = 0; s < headB.tree_size; s += 1000) all = all.concat((await get(`${W}/v1/witness/log/entries?start=${s}&count=1000`)).entries);
const mem9 = (await get(`${W}/v1/witness/statements?recorder_key=${rpub}&session_fp=${sfp}`)).statements;
r = L.monitor(all.slice(0, headB.tree_size), headB, c, { ...pin, recorderKey: rpub, sessionFp: sfp, memory: mem9 });
ok("a monitor rebuilds the tree head from every entry and finds the session's 9 statements", r.ok && r.session === 9, JSON.stringify(r.kinds));

// 4. COSE receipt for one statement, checked here and by pycose (independent CBOR and COSE code).
const idx0 = proofs.entries[0].leaf_index;
const rc = await get(`${W}/v1/witness/log/receipt?index=${idx0}&tree_size=${headB.tree_size}`, "bytes");
r = L.checkReceipt(rc, new TextEncoder().encode(canon(mem[0])), c, { ...pin, head: headB });
ok("RFC 9942 receipt proves the statement into the same root as the tree head", r.ok, JSON.stringify({ size: r.tree_size, index: r.leaf_index, sub: r.sub && r.sub.slice(0, 12) }));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "rcpt-"));
fs.writeFileSync(path.join(tmp, "r.cbor"), rc); fs.writeFileSync(path.join(tmp, "e.bin"), canon(mem[0]));
const py = `
import sys, hashlib, cbor2
from pycose.messages import Sign1Message
from pycose.keys import OKPKey
from pycose.keys.curves import Ed25519
import base64
raw = open(sys.argv[1],'rb').read(); entry = open(sys.argv[2],'rb').read(); pub = base64.urlsafe_b64decode(sys.argv[3] + '==')
H = lambda b: hashlib.sha256(b).digest()
tag = cbor2.loads(raw); assert tag.tag == 18
prot, unprot, payload, sig = tag.value
ph = cbor2.loads(prot); assert ph[1] == -8 and ph[395] == 1
size, idx, path = cbor2.loads(unprot[396][-1][0])
fn, sn, r = idx, size - 1, H(b'\\0' + entry)
for p in path:
    if fn & 1 or fn == sn:
        r = H(b'\\1' + p + r)
        if not fn & 1:
            while not fn & 1 and fn: fn >>= 1; sn >>= 1
    else: r = H(b'\\1' + r + p)
    fn >>= 1; sn >>= 1
assert sn == 0
msg = Sign1Message.from_cose_obj([prot, dict(unprot), payload, sig], True); msg.payload = r  # cbor2 6 decodes arrays as tuples and maps as frozen maps, which pycose 1.1 rejects in decode()
msg.key = OKPKey(crv=Ed25519, x=pub)
print("pycose", msg.verify_signature(), size, idx, r.hex()[:16])
`;
fs.writeFileSync(path.join(tmp, "v.py"), py);
let pyOut = ""; try { pyOut = execFileSync("python3", [path.join(tmp, "v.py"), path.join(tmp, "r.cbor"), path.join(tmp, "e.bin"), key], { encoding: "utf8" }).trim(); } catch (e) { pyOut = String(e.stderr || e.message).slice(-300); }
ok("pycose verifies the same receipt with its own CBOR and COSE code", /^pycose True/.test(pyOut) && pyOut.includes(headB.root_hash.slice(0, 16)), pyOut);

// 5. SCITT registration: the recorder key signs a COSE Signed Statement, the witness registers it.
const te = new TextEncoder();
const prot = C.encode(new Map([[1, -8], [3, "application/json"], [4, te.encode(rpub)], [15, new Map([[1, "hive-recorder:" + rpub], [2, sfp]])]]));
const payload = te.encode(canon({ count: 9, head: mem9[8].head, recorder_key: rpub, session_fp: sfp }));
const sig = new Uint8Array(crypto.sign(null, C.encode(["Signature1", prot, new Uint8Array(0), payload]), rk));
const ss = C.encode(new C.Tag(18, [prot, new Map(), payload, sig]));
const reg = await fetch(W + "/entries", { method: "POST", headers: { "content-type": "application/cose" }, body: ss });
const regRc = new Uint8Array(await reg.arrayBuffer());
r = L.checkReceipt(regRc, ss, c, pin);
ok("SCRAPI POST /entries returns 201, a Location and a receipt for the Signed Statement", reg.status === 201 && /^\/entries\/\d+$/.test(reg.headers.get("location") || "") && r.ok, `${reg.status} ${reg.headers.get("location")}`);
const transparent = C.encode(new C.Tag(18, [prot, new Map([[394, [regRc]]]), payload, sig]));
const ts = C.decode(transparent), emptied = C.encode(new C.Tag(18, [ts.value[0], new Map(), ts.value[2], ts.value[3]]));
r = L.checkReceipt(ts.value[1].get(394)[0], emptied, c, pin);
ok("the Transparent Statement (receipt in header 394) checks on its own", r.ok);
const bad = ss.slice(); bad[bad.length - 1] ^= 1;
const rej = await fetch(W + "/entries", { method: "POST", headers: { "content-type": "application/cose" }, body: bad });
ok("a Signed Statement with a broken signature is refused by the registration policy", rej.status === 400, String((await rej.json()).error));
const keys = C.decode(await get(W + "/.well-known/scitt-keys", "bytes"));
ok("/.well-known/scitt-keys serves the witness key as a COSE Key Set", Array.isArray(keys) && Buffer.from(keys[0].get(-2)).toString("base64url") === key);

// 6. Two outside cosigners (stand-ins for ICE and the firm) check consistency and cosign.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cosign-"));
const cos = [["ice.example/cosigner", "ice"], ["firm.example/cosigner", "firm"]].map(([name, f]) => {
  const k = path.join(dir, f + ".pem"); const pub = execFileSync("node", ["vendor-kit/cosigner.mjs", "keygen", "--key", k], { encoding: "utf8" }).trim();
  return { name, key: pub, pem: k, state: path.join(dir, f + ".json") };
});
const origin = (await get(W + "/v1/witness/log")).origin;
const pullCmd = w => JSON.parse(execFileSync("node", ["vendor-kit/cosigner.mjs", "pull", "--log", W, "--log-key", key, "--origin", origin, "--name", w.name, "--key", w.pem, "--state", w.state, "--post"], { encoding: "utf8" }));
for (const w of cos) pullCmd(w);
for (let i = 10; i <= 12; i++) await witness(W, sfp, i);
const second = cos.map(pullCmd);
ok("each cosigner proves the log grew from the tree it last signed before signing again", second.every(x => x.from_size > 0 && x.proof_hashes > 0 && x.posted.status === 200), second.map(x => `${x.from_size}->${x.cosigned}`).join(" "));
const cp = await get(W + "/v1/witness/log/checkpoint?tree_size=" + second[0].cosigned, "text");
r = L.checkCheckpoint(cp, c, { origin, logKey: key, cosigners: cos.map(({ name, key }) => ({ name, key })), quorum: 2 });
ok("the checkpoint carries the log signature and both outside cosignatures (quorum 2 of 2)", r.ok && r.cosigned.length === 2, r.why || r.cosigned.map(x => x.name).join(", "));

// Tamper cases.
const T = (name, step, res) => ok("tamper " + name + " -> " + step, !res.ok && res.step === step, res.why);
T("statement-dropped-from-answer", "LOGGED", L.checkLogged(mem.slice(1), proofs, c, pin));
T("statement-not-in-log", "LOGGED", L.checkLogged(mem, { ...proofs, entries: proofs.entries.slice(1) }, c, pin));
T("statement-edited", "INCLUDED", L.checkLogged(mem.map((s, i) => i === 2 ? { ...s, count: 99 } : s), proofs, c, pin));
T("head-root-rewritten", "HEAD", L.checkLogged(mem, { ...proofs, head: { ...proofs.head, root_hash: "0".repeat(64) } }, c, pin));
T("memory-hides-a-line", "HIDDEN", L.monitor(all.slice(0, headB.tree_size), headB, c, { ...pin, recorderKey: rpub, sessionFp: sfp, memory: mem9.filter((_, i) => i !== 4) }));
T("entry-rewritten", "ROOT", L.monitor(all.slice(0, headB.tree_size).map((e, i) => i === idx0 ? { ...e, entry: e.entry.replace(/"count":1/, '"count":2') } : e), headB, c, pin));
const rc2 = rc.slice(); rc2[rc2.length - 5] ^= 1;
T("receipt-signature-flipped", "RECEIPT", L.checkReceipt(rc2, new TextEncoder().encode(canon(mem[0])), c, pin));
T("receipt-for-another-statement", "RECEIPT", L.checkReceipt(rc, new TextEncoder().encode(canon(mem[1])), c, pin));
T("checkpoint-one-cosigner-short", "COSIGNED", L.checkCheckpoint(cp.split("\n").filter(l => !l.includes("firm.example")).join("\n"), c, { origin, logKey: key, cosigners: cos, quorum: 2 }));
T("consistency-proof-altered", "SPLIT", L.checkHeads(headA, headB, cons.path.map((h, i) => i === 0 ? "f".repeat(64) : h), c, pin));

// Split view: a second witness with the same key and another history. Its heads verify, but they
// do not extend the first witness's, and an honest cosigner refuses them.
let forkOk = false; try { forkOk = (await get(FORK + "/v1/witness/key")).witness_key === key; } catch {}
if (forkOk) {
  for (let i = 1; i <= 20; i++) await witness(FORK, crypto.randomBytes(32).toString("hex"), 1);
  const fh = await get(FORK + "/v1/witness/log/head?tree_size=" + headB.tree_size);
  T("same-size-different-tree", "SPLIT", L.checkHeads(headB, fh, [], c, pin));
  const later = await get(FORK + "/v1/witness/log/head");
  const fcons = await get(`${FORK}/v1/witness/log/consistency?first=${headB.tree_size}&second=${later.tree_size}`);
  T("fork-presented-as-growth", "SPLIT", L.checkHeads(headB, later, fcons.path, c, pin));
  let refused = ""; try { execFileSync("node", ["vendor-kit/cosigner.mjs", "pull", "--log", FORK, "--log-key", key, "--origin", origin, "--name", cos[0].name, "--key", cos[0].pem, "--state", cos[0].state], { encoding: "utf8", stdio: "pipe" }); } catch (e) { refused = String(e.stderr); }
  ok("tamper fork-shown-to-cosigner -> the ICE stand-in cosigner refuses to sign", /refused:/.test(refused), refused.trim());
} else console.log("SKIP fork cases (no second witness at " + FORK + ")");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
