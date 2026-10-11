#!/usr/bin/env node
// The firm fixes its weights before it asks for data: it commits to them (lib/commit.mjs) and registers the
// commitment, signed with its own key, on the public log. The weights and salt stay with the firm.
//   node commit-weights.mjs --portfolio book.csv --customer firm-demo-5 --key firm.pem --iss <issuer> --for <verification_key_sha256>
//                           --private weights.private.json --out weights   (writes weights.json, .signed-statement.cose, .receipt.cose)
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { commitVector, newSalt, saltToText, SCHEME, N } from "../vendor-kit/lib/commit.mjs";
const opt = n => { const i = process.argv.indexOf("--" + n); return i > 0 ? process.argv[i + 1] : undefined; };
const rows = fs.readFileSync(opt("portfolio"), "utf8").trim().split("\n").slice(1).map(l => l.split(","));
if (rows.length !== N) throw new Error("the book must list " + N + " bonds");
const ids = rows.map(r => r[0].trim()), par = rows.map(r => BigInt(r[2].trim()));
const salt = newSalt();
const doc = { kind: "hive.portfolio-commitment/1", customer: opt("customer"), scheme: SCHEME, n: N, value: "par_thousands", commitment: commitVector(ids, par, salt),
  for_calculation: opt("for"), committed_at: new Date().toISOString() };
fs.writeFileSync(opt("private"), JSON.stringify({ ids, par_thousands: par.map(String), salt: saltToText(salt) }, null, 1) + "\n", { mode: 0o600 });
fs.writeFileSync(opt("out") + ".json", JSON.stringify(doc, null, 1) + "\n");
const here = new URL(".", import.meta.url).pathname;
console.log(execFileSync(process.execPath, [here + "../vendor-kit/scitt-register.mjs", "--log", opt("log") || "https://witness.thehiveryiq.com", "--key", opt("key"), "--iss", opt("iss"), "--sub", "hive.portfolio-commitment/1", "--in", opt("out") + ".json", "--out", opt("out")]).toString().trim());
