#!/usr/bin/env node
// Register a JSON document on the witness's log as a SCITT Signed Statement (RFC 9943) over SCRAPI.
// The issuer signs with its own Ed25519 key; the witness returns an RFC 9942 receipt, and this writes
// the Transparent Statement (the Signed Statement with the receipt in header 394).
//   node scitt-register.mjs --log https://witness.thehiveryiq.com --key issuer.pem --iss <issuer> --sub <subject>
//                           --in doc.json --out prefix     -> prefix.signed-statement.cose, prefix.receipt.cose, prefix.transparent.cose
import fs from "node:fs";
import crypto from "node:crypto";
import * as C from "../plugins/hive-recorder/scripts/cose.mjs";
import { canon } from "../plugins/hive-recorder/scripts/core.mjs";

const opt = n => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : undefined; };
const sk = crypto.createPrivateKey(fs.readFileSync(opt("key")));
const pub = crypto.createPublicKey(sk).export({ format: "jwk" }).x;
const te = new TextEncoder();
const prot = C.encode(new Map([[1, C.ALG_EDDSA], [3, "application/json"], [4, te.encode(pub)], [15, new Map([[1, opt("iss")], [2, opt("sub")]])]]));
const payload = te.encode(canon(JSON.parse(fs.readFileSync(opt("in"), "utf8"))));
const sig = new Uint8Array(crypto.sign(null, C.encode(["Signature1", prot, new Uint8Array(0), payload]), sk));
const ss = C.encode(new C.Tag(18, [prot, new Map(), payload, sig]));
const r = await fetch(opt("log") + "/entries", { method: "POST", headers: { "content-type": "application/cose", accept: "application/cose" }, body: ss });
if (r.status !== 201) { console.error("registration refused:", r.status, await r.text()); process.exit(2); }
const receipt = new Uint8Array(await r.arrayBuffer());
const ts = C.encode(new C.Tag(18, [prot, new Map([[C.H_RECEIPTS, [receipt]]]), payload, sig]));
const out = opt("out");
fs.writeFileSync(out + ".signed-statement.cose", ss); fs.writeFileSync(out + ".receipt.cose", receipt); fs.writeFileSync(out + ".transparent.cose", ts);
const rr = C.readReceipt(receipt);
console.log(JSON.stringify({ location: r.headers.get("location"), issuer_key: pub, payload_bytes: payload.length, tree_size: rr.proof[0], leaf_index: rr.proof[1] }));
