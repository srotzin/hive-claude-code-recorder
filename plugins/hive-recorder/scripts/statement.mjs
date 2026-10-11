#!/usr/bin/env node
// Build a licence statement for one vendor, and let the vendor accept one.
// Run by whoever holds the recorder (it signs with the recorder key), and by the vendor (it signs with its own key).
//   node statement.mjs build --vendor <name> --from <iso> --to <iso> --out <dir> <session.jsonl>...   [HIVE_RECORDER_DIR for the key]
//     writes statement.json and one copy per session for that vendor (its lines in full, the rest digest only)
//   node statement.mjs accept <statement.json> --vendor-key-pem <file> --out <statement.json>
//   node statement.mjs match --vendor <name> --log <deliveries.jsonl> --vendor-key-pem <file> --from <iso> --to <iso> --out <match.json> <copy.jsonl>...
//     the vendor matches its own delivery log against the firm's copies for it, and signs the result
//   node statement.mjs match-accept <match.json> --out <match.json>   [HIVE_RECORDER_DIR for the key]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { canon, discloseFor, statementBody, matchBody } from "./core.mjs";
import { c } from "./verify.mjs";
const args = process.argv.slice(2);
const opt = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : undefined; };
const readLines = f => fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
if (args[0] === "build") {
  const vendor = opt("--vendor"), out = opt("--out"), period = { from: new Date(opt("--from")).toISOString(), to: new Date(opt("--to")).toISOString() };
  const files = args.slice(1).filter((a, i, all) => !a.startsWith("--") && !all[i].startsWith("--") && !(i > 0 && all[i - 1].startsWith("--")));
  const dir = process.env.HIVE_RECORDER_DIR || path.join(os.homedir(), ".hive-recorder");
  const sk = crypto.createPrivateKey(fs.readFileSync(path.join(dir, "keys", "recorder-ed25519.pem")));
  fs.mkdirSync(out, { recursive: true });
  const discs = files.map(f => discloseFor(readLines(f), vendor, c.sha256hex));
  discs.forEach((d, i) => fs.writeFileSync(path.join(out, "session-" + (i + 1) + "." + vendor + ".jsonl"), d.map(l => JSON.stringify(l)).join("\n") + "\n"));
  const b = { ...statementBody(discs, vendor, period, c), issued_at: new Date().toISOString() };
  const st = { ...b, sig: crypto.sign(null, Buffer.from(canon(b)), sk).toString("base64url") };
  fs.writeFileSync(path.join(out, "statement.json"), JSON.stringify(st, null, 1));
  console.log(`statement for ${vendor}: ${st.sessions.length} sessions, ${st.usage.reduce((a, u) => a + u.asked, 0)} pulls, ${st.outside.length} outside the entitlement`);
} else if (args[0] === "accept") {
  const { accepted, ...st } = JSON.parse(fs.readFileSync(args[1], "utf8"));
  const k = crypto.createPrivateKey(fs.readFileSync(opt("--vendor-key-pem")));
  const a = { accepted_at: new Date().toISOString() };
  const sig = crypto.sign(null, Buffer.from(canon({ statement_sha256: c.sha256hex(canon(st)), ...a })), k).toString("base64url");
  fs.writeFileSync(opt("--out"), JSON.stringify({ ...st, accepted: { vendor_key: crypto.createPublicKey(k).export({ format: "jwk" }).x, ...a, sig } }, null, 1));
  console.log("accepted");
} else if (args[0] === "match") {
  const vendor = opt("--vendor"), period = { from: new Date(opt("--from")).toISOString(), to: new Date(opt("--to")).toISOString() };
  const skip = new Set(["--vendor", "--log", "--vendor-key-pem", "--from", "--to", "--out"]);
  const files = args.slice(1).filter((a, i, all) => !skip.has(a) && !skip.has(all[i]) && !(i > 0 && skip.has(all[i - 1])));
  const k = crypto.createPrivateKey(fs.readFileSync(opt("--vendor-key-pem")));
  const b = { ...matchBody(files.map(readLines), readLines(opt("--log")), vendor, period, c), issued_at: new Date().toISOString(), vendor_key: crypto.createPublicKey(k).export({ format: "jwk" }).x };
  const m = { ...b, sig: crypto.sign(null, Buffer.from(canon(b)), k).toString("base64url") };
  fs.writeFileSync(opt("--out"), JSON.stringify(m, null, 1));
  console.log(`delivery match for ${vendor}: ${m.matches.length} matched, ${m.unrecorded.length} delivered with no record, ${m.unmatched.length} recorded with no delivery`);
} else if (args[0] === "match-accept") {
  const { accepted, ...m } = JSON.parse(fs.readFileSync(args[1], "utf8"));
  const dir = process.env.HIVE_RECORDER_DIR || path.join(os.homedir(), ".hive-recorder");
  const sk = crypto.createPrivateKey(fs.readFileSync(path.join(dir, "keys", "recorder-ed25519.pem")));
  const a = { accepted_at: new Date().toISOString() };
  const sig = crypto.sign(null, Buffer.from(canon({ match_sha256: c.sha256hex(canon(m)), ...a })), sk).toString("base64url");
  fs.writeFileSync(opt("--out"), JSON.stringify({ ...m, accepted: { recorder_key: crypto.createPublicKey(sk).export({ format: "jwk" }).x, ...a, sig } }, null, 1));
  console.log("accepted by the firm");
} else { console.log("usage: statement.mjs build|accept|match|match-accept ..."); process.exitCode = 2; }
