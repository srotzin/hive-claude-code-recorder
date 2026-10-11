// Delivery log for a data vendor's server. One log per customer. Each delivery is signed with the
// vendor's key, chained to the one before it, and its head sent to a witness before the data goes out.
// The delivery id goes back to the customer inside the result, so the customer's recorder can keep a
// fingerprint of it. The vendor keeps the delivered body in a private side file; only fingerprints
// leave the vendor (the vendor key, a hash of the log name, a count and a head hash).
import fs from "node:fs";
import crypto from "node:crypto";

export const DELIVERY_FORMAT = "hive.vendor-delivery/1";
export function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).filter(k => v[k] !== undefined).sort()
    .map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const readLines = f => { try { return fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l)); } catch { return []; } };
// Letters only, so the id never adds figures to the result.
export const newDeliveryId = () => "dl-" + Array.from(crypto.randomBytes(24), b => String.fromCharCode(97 + (b % 26))).join("");

//   { file, keyPem, vendor, customer, log, witnesses: [url], timeoutMs }
export function openDeliveryLog(o) {
  const sk = crypto.createPrivateKey(fs.readFileSync(o.keyPem));
  const pub = crypto.createPublicKey(sk).export({ format: "jwk" }).x;
  const logFp = sha(o.log);
  return {
    pub, logFp,
    async deliver(d) { return (await this.deliverFull(d)).id; },
    // Same, and says how many witnesses countersigned before it returned, so a gateway can hold the data.
    async deliverFull({ tool, datasets, body, requireWitness }) {
      const lines = readLines(o.file), last = lines[lines.length - 1];
      const id = newDeliveryId();
      const b = { v: DELIVERY_FORMAT, seq: lines.length, prev: last ? last.hash : "0".repeat(64), t: new Date().toISOString(),
        vendor: o.vendor, customer: o.customer, log: logFp, tool, datasets: [...datasets].sort(), delivery_fp: sha(id), body_sha256: sha(canon(body)) };
      const line = { ...b, hash: sha(canon(b)), sig: crypto.sign(null, Buffer.from(canon(b)), sk).toString("base64url") };
      const keep = () => {
        fs.appendFileSync(o.file, JSON.stringify(line) + "\n");
        fs.appendFileSync(o.file.replace(/\.jsonl$/, ".private.jsonl"), JSON.stringify({ seq: b.seq, delivery_id: id, body }) + "\n", { mode: 0o600 });
      };
      // Without requireWitness the line is kept first, as before. With it, the line is kept only once a
      // witness has countersigned it, so a delivery the gateway withheld never enters the log.
      if (!requireWitness) keep();
      const req = { count: b.seq + 1, head: line.hash, recorder_key: pub, session_fp: logFp };
      const req_sig = crypto.sign(null, Buffer.from(canon(req)), sk).toString("base64url");
      let witnessed = 0;
      await Promise.all((o.witnesses || []).map(async url => {
        try {
          const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...req, req_sig }), signal: AbortSignal.timeout(o.timeoutMs || 8000) });
          if (r.ok) { fs.appendFileSync(o.file.replace(/\.jsonl$/, ".witness.jsonl"), JSON.stringify(await r.json()) + "\n"); witnessed++; }
          else fs.appendFileSync(o.file + ".errors.log", new Date().toISOString() + " witness HTTP " + r.status + "\n");
        } catch (e) { fs.appendFileSync(o.file + ".errors.log", new Date().toISOString() + " witness " + e.message + "\n"); }
      }));
      if (requireWitness) { if (!witnessed) return { id: null, seq: b.seq, witnessed: 0 }; keep(); }
      return { id, seq: b.seq, witnessed };
    },
  };
}
