#!/usr/bin/env node
// Checks an answer passport offline. Pins default to the live demo keys; pass --pins pins.json to use others.
//   node verify.mjs passport.json [--pins pins.json]
import fs from "node:fs";
import crypto from "node:crypto";
import * as snarkjs from "snarkjs";
import { verifyPassport } from "./verify-core.mjs";

export const LIVE_PINS = {
  group_key: "xu6G1gCIcQNIfWSNXB7SwR1sSg2sMME-yjjSLcX495Q",
  firm_key: "H0IKgSzUtuAA-CrTRW8N81Z5w2AjxYWzOn07gYw9iw0",
  vendor_key: "fzRLBYluTLJaa2DW8T11AaBbIH2OUE8hk8akjX9BNgI",
  log_key: "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE",
  origin: "witness.thehiveryiq.com/log",
};
const ed = k => crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: k }, format: "jwk" });
export const nodeDeps = {
  c: {
    sha256: u => new Uint8Array(crypto.createHash("sha256").update(u).digest()),
    sha256hex: s => crypto.createHash("sha256").update(s).digest("hex"),
    verify: (k, m, s) => { try { return crypto.verify(null, Buffer.from(m), ed(k), Buffer.from(s, "base64url")); } catch { return false; } },
    verifyBytes: (k, m, s) => { try { return crypto.verify(null, Buffer.from(m), ed(k), Buffer.from(s)); } catch { return false; } },
  },
  plonkVerify: (vk, sig, proof) => snarkjs.plonk.verify(vk, sig, proof, { info() {}, debug() {}, warn() {}, error() {} }),
};
if (import.meta.url === "file://" + process.argv[1]) {
  const i = process.argv.indexOf("--pins");
  const pins = i > 0 ? JSON.parse(fs.readFileSync(process.argv[i + 1], "utf8")) : LIVE_PINS;
  const r = await verifyPassport(JSON.parse(fs.readFileSync(process.argv[2], "utf8")), pins, nodeDeps);
  for (const s of r.steps) console.log((s.ok ? "PASS " : "FAIL ") + s.step.padEnd(10) + (s.what || s.why));
  console.log(r.ok ? `\nThe answer's ${r.figure} ${r.unit} is the approved calculation over the delivered data and committed weights.` : `\nRefused at ${r.step}.`);
  process.exit(r.ok ? 0 : 1);
}
