// hive.agent-action/1 core. Pure functions shared by the recorder, the verifier,
// the witness and the browser checker. Crypto is passed in, so this file has no imports.

export const FORMAT = "hive.agent-action/1";
export const WITNESS_FORMAT = "hive.agent-action-witness/1";
export const ZERO = "0".repeat(64);

// Canonical JSON: object keys sorted, no whitespace, arrays kept in order.
export function canon(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).filter(k => v[k] !== undefined).sort()
    .map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}

// The part of a line that is hashed and signed: everything except hash and sig.
// sig_pq (the optional ML-DSA-65 signature) is over the same body.
export function body(line) {
  const { hash, sig, sig_pq, ...rest } = line;
  return rest;
}

// Split lines (format 1.3). A line with form "split" is hashed and signed over its digest form:
// the public fields below, plus one fingerprint of everything else (which carries a random nonce,
// so it can't be guessed). Whoever holds the record can then hand someone a copy where some lines
// are only their digest form. Those lines still chain, still sign and still match what the witness
// saw, so nothing can be removed, while what they say stays private.
export const PUBLIC = ["v", "seq", "prev", "t", "key", "event", "session", "form", "vendor"];
export function digestOf(b, sha256hex) {
  const pub = {}, priv = {};
  for (const [k, v] of Object.entries(b)) (PUBLIC.includes(k) ? pub : priv)[k] = v;
  return { ...pub, private_fp: sha256hex(canon(priv)) };
}
// The exact bytes a line's hash and signatures cover.
export function signable(line, sha256hex) {
  const b = body(line);
  if (line.form !== "split") return canon(b);
  if (line.redacted === true) { const { redacted, ...d } = b; return canon(d); }
  return canon(digestOf(b, sha256hex));
}
// A copy of a line showing only its digest form.
export function stubOf(line, sha256hex) {
  if (line.form !== "split" || line.redacted) return line;
  const out = { ...digestOf(body(line), sha256hex), hash: line.hash, sig: line.sig, redacted: true };
  if (line.sig_pq) out.sig_pq = line.sig_pq;
  return out;
}
// The vendor behind a tool: the MCP server in mcp__<server>__<tool>.
export function vendorOf(name) { const m = /^mcp__([A-Za-z0-9_.-]+?)__/.exec(String(name || "")); return m ? m[1] : undefined; }
// A copy of a record for one vendor: its own lines, the turn ends and every unsplit line in full,
// everything else as digest form.
export function discloseFor(lines, vendor, sha256hex) {
  return lines.map(l => (l.form !== "split" || l.vendor === vendor || (!l.vendor && (l.event === "Stop" || l.event === "SubagentStop"))) ? l : stubOf(l, sha256hex));
}
// Figures in a text, normalised, for linking an answer to the tool results it drew on.
// Skips one and two digit integers and years, which match too much by chance.
export function numbersIn(text) {
  const out = new Set();
  for (const m of String(text).matchAll(/-?\d{1,3}(?:,\d{3})+(?:\.\d+)?|-?\d+(?:\.\d+)?/g)) {
    const n = Number(m[0].replace(/,/g, ""));
    if (!Number.isFinite(n)) continue;
    const isInt = Number.isInteger(n), a = Math.abs(n);
    if (isInt && (a < 100 || (a >= 1900 && a <= 2100))) continue;
    out.add(String(n));
  }
  return [...out];
}

// Glob match. "**" matches anything, "*" matches anything except sep, "?" one character.
export function globMatch(pattern, s, sep = "/") {
  const e = c => c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  const ns = "[^" + e(sep) + "]";
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "*" && pattern[i + 1] === "*") { re += ".*"; i++; if (pattern[i + 1] === sep) { re = re.slice(0, -2) + "(?:.*" + e(sep) + ")?"; i++; } }
    else if (ch === "*") re += ns + "*";
    else if (ch === "?") re += ns;
    else re += e(ch);
  }
  return new RegExp("^" + re + "$").test(s);
}

// Scope check against a signed admission. Pure, so the verifier can re-run it.
//   scope:   { tools: [globs], paths: [globs], hosts: [globs] }
//   tool:    tool name
//   touched: { paths: [...], hosts: [...] }
export function checkScope(scope, tool, touched) {
  const any = (list, v, sep) => (list || []).some(p => globMatch(p, v, sep));
  return {
    tool: !any(scope.tools, tool, "\u0000"),
    // Paths inside the project are recorded relative to it. An absolute path (outside the
    // project) can only match an admitted pattern that is itself absolute.
    paths: (touched.paths || []).filter(p => !(scope.paths || []).some(g => (p[0] === "/") === (g[0] === "/") && globMatch(g, p, "/"))),
    hosts: (touched.hosts || []).filter(h => !any(scope.hosts, h, ".")),
    // Datasets, feeds and products named in a tool's input (licensed data reached through MCP tools).
    // Only checked when the admission lists datasets.
    ...(scope.datasets ? { datasets: (touched.datasets || []).filter(d => !any(scope.datasets, d, ".")) } : {}),
  };
}
// The scope an admission policy gives. The recorder and the checker both use this.
export function scopeOf(p) {
  const list = v => Array.isArray(v) ? v.map(String).sort() : [];
  return { tools: list(p.tools), paths: list(p.paths), hosts: list(p.hosts).map(h => h.toLowerCase()), ...(Array.isArray(p.datasets) ? { datasets: list(p.datasets) } : {}) };
}
export function isOutside(o) { return !!(o && (o.tool || (o.paths && o.paths.length) || (o.hosts && o.hosts.length) || (o.datasets && o.datasets.length))); }

export const GATES = ["FORMAT", "KEY_PIN", "CHAIN_ORDER", "ENTRY_HASH", "SIGNATURE", "PQ_SIGNATURE", "DISCLOSURE", "SEAL", "ADMISSION", "WITNESS", "TIMESTAMP"];

// Verify one session record.
//   lines:    array of parsed JSON lines
//   c:        { sha256hex(str) -> hex, verify(pubB64url, msgStr, sigB64url) -> bool,
//               verifyPq?(pubB64url, msgStr, sigB64url) -> bool  (ML-DSA-65, optional) }
//   opts:     { pin: public key (b64url) expected, witnesses: [statements], witnessPin: b64url,
//               admissionPin: sha256 of the canonical admission policy the reviewer expects,
//               admissionScope: the scope that policy gives, from scopeOf(policy),
//               witnessPins: [b64url] witness keys accepted (any of them),
//               minWitnesses: how many different pinned witnesses must have signed (default 0),
//               maxLagSec: a statement signed longer than this after its line was written fails,
//               requireWitness: no statements is a failure, not NONE,
//               requireFullCoverage: every line, up to the last, must be covered by a statement,
//               timestamps: [{ count, head, ok, gen_time, tsa }] RFC 3161 tokens already checked by the caller,
//               requireTimestamp: no timestamp is a failure, not NONE,
//               requireEnd: the record must finish with SessionEnd and a seal,
//               memory: { statements, from } fetched from the witness for this session,
//               requireMemory: the witness must remember this session,
//               allowRedacted: accept a copy where some split lines are digest form only,
//               discloseFor: vendor name; every line of that vendor must be shown in full }
export function verifyRecord(lines, c, opts = {}) {
  const res = { ok: false, gates: {}, first_failure: null, entries: lines.length, summary: null };
  const fail = (g, why) => { if (!res.first_failure) res.first_failure = { gate: g, why }; res.gates[g] = "FAIL"; };
  const pass = g => { if (res.gates[g] !== "FAIL") res.gates[g] = "PASS"; };
  if (!Array.isArray(lines) || lines.length === 0) { fail("FORMAT", "empty record"); return res; }

  // FORMAT
  const start = lines[0];
  for (const [i, l] of lines.entries()) {
    if (!l || l.v !== FORMAT || typeof l.seq !== "number" || typeof l.hash !== "string" || typeof l.sig !== "string" || typeof l.event !== "string") { fail("FORMAT", "line " + i + " is not " + FORMAT); return res; }
    if (l.redacted !== undefined && (l.redacted !== true || l.form !== "split" || typeof l.private_fp !== "string" || Object.keys(l).some(k => !PUBLIC.includes(k) && !["private_fp", "redacted", "hash", "sig", "sig_pq"].includes(k)))) { fail("FORMAT", "line " + i + " is a malformed digest-only line"); return res; }
  }
  if (start.event !== "RecorderKey" || typeof start.public_key !== "string") { fail("FORMAT", "first line must publish the recorder key"); return res; }
  pass("FORMAT");

  // KEY_PIN
  const pub = start.public_key;
  if (opts.pin && opts.pin !== pub) fail("KEY_PIN", "record was signed by a key other than the pinned one");
  for (const l of lines) if (l.key !== start.key_id) { fail("KEY_PIN", "line " + l.seq + " names a different key"); break; }
  pass("KEY_PIN");

  // CHAIN_ORDER, ENTRY_HASH, SIGNATURE
  let prev = ZERO;
  for (const [i, l] of lines.entries()) {
    if (l.seq !== i) { fail("CHAIN_ORDER", "expected seq " + i + ", found " + l.seq); break; }
    if (l.prev !== prev) { fail("CHAIN_ORDER", "line " + i + " does not point to the line before it"); break; }
    const b = signable(l, c.sha256hex);
    if (c.sha256hex(b) !== l.hash) { fail("ENTRY_HASH", "line " + i + " changed after it was signed"); break; }
    if (!c.verify(pub, b, l.sig)) { fail("SIGNATURE", "line " + i + " signature does not verify"); break; }
    prev = l.hash;
  }
  pass("CHAIN_ORDER"); pass("ENTRY_HASH"); pass("SIGNATURE");

  // PQ_SIGNATURE: if the recorder key line names an ML-DSA-65 key, every line must carry a valid sig_pq.
  if (start.pq_public_key) {
    if (typeof c.verifyPq !== "function") res.gates.PQ_SIGNATURE = "NOT_CHECKED";
    else {
      for (const [i, l] of lines.entries()) {
        if (typeof l.sig_pq !== "string" || !c.verifyPq(start.pq_public_key, signable(l, c.sha256hex), l.sig_pq)) { fail("PQ_SIGNATURE", "line " + i + " ML-DSA-65 signature is missing or does not verify"); break; }
      }
      pass("PQ_SIGNATURE");
    }
  } else res.gates.PQ_SIGNATURE = "NONE";

  // DISCLOSURE: a copy with digest-only lines is only accepted when the reviewer asked for one,
  // and every line of the vendor it was made for must be shown in full.
  const stubs = lines.filter(l => l.redacted === true);
  res.redacted = stubs.length;
  if (stubs.length && !opts.allowRedacted) fail("DISCLOSURE", "this copy shows " + stubs.length + " lines as digest only; check it as a disclosure");
  else if (opts.discloseFor) {
    const hid = stubs.find(l => l.vendor === opts.discloseFor);
    if (hid) fail("DISCLOSURE", "line " + hid.seq + " is a " + opts.discloseFor + " line, and this copy hides it");
    else pass("DISCLOSURE");
  } else if (stubs.length) pass("DISCLOSURE");
  else res.gates.DISCLOSURE = "NONE";

  // SEAL: every Seal line must cover exactly the lines before it.
  const seals = lines.filter(l => l.event === "Seal");
  for (const s of seals) {
    const before = lines[s.seq - 1];
    if (s.count !== s.seq || !before || s.head !== before.hash) { fail("SEAL", "seal at line " + s.seq + " does not match the lines before it"); break; }
  }
  if (opts.requireEnd) {
    const n = lines.length;
    if (n < 2 || lines[n - 1].event !== "Seal" || lines[n - 2].event !== "SessionEnd") fail("SEAL", "the record stops before the session ended: it must finish with SessionEnd and a seal");
  }
  pass("SEAL");
  const last = lines[lines.length - 1];
  res.sealed = last.event === "Seal";
  res.open_tail = res.sealed ? 0 : lines.length - 1 - (seals.length ? seals[seals.length - 1].seq : 0);

  // ADMISSION: the signed scope must come before anything happened, and every recorded
  // scope check must be what the admission says. The verifier re-runs the check itself.
  const adm = lines.filter(l => l.event === "Admission");
  if (adm.length) {
    const a = adm[0];
    if (adm.length > 1 || a.seq !== 1) fail("ADMISSION", "the admission must be line 1, before anything happened, and appear once");
    else if (opts.admissionPin && a.policy_sha256 !== opts.admissionPin) fail("ADMISSION", "the admission in this record is not the policy you expected");
    else if (opts.admissionScope && canon(a.scope) !== canon(opts.admissionScope)) fail("ADMISSION", "the admission's scope is not the scope in the policy you expected");
    else {
      // Entitlements: one split line per vendor, right after the admission, listing that vendor's datasets.
      const ents = lines.filter(l => l.event === "Entitlement");
      const entOf = {}, hiddenEnt = new Set();
      ents.forEach((e, k) => {
        if (e.seq !== 2 + k) fail("ADMISSION", "entitlement at line " + e.seq + " must follow the admission directly");
        if (e.redacted) hiddenEnt.add(e.vendor); else entOf[e.vendor] = Array.isArray(e.datasets) ? e.datasets : [];
      });
      for (const l of lines) {
        if (l.event !== "PreToolUse" || l.redacted) continue;
        if (!l.scope || !l.scope.touched) { fail("ADMISSION", "line " + l.seq + " has no scope check"); break; }
        if (ents.length && l.vendor && hiddenEnt.has(l.vendor)) { fail("ADMISSION", "line " + l.seq + " is shown, and the " + l.vendor + " entitlement it is checked against is hidden"); break; }
        const sc = ents.length ? { ...a.scope, datasets: entOf[l.vendor] || [] } : a.scope;
        const want = checkScope(sc, l.tool.name, l.scope.touched);
        if (canon(want) !== canon(l.scope.outside)) { fail("ADMISSION", "line " + l.seq + " scope check does not match the admission"); break; }
      }
    }
    pass("ADMISSION");
  } else res.gates.ADMISSION = "NONE";

  // WITNESS: each statement must sign a head that is in this chain at that count.
  // With memory (statements fetched from the witness itself), every statement the witness remembers
  // for this session must hold against this record, not only the ones whoever handed it over chose to include.
  const mem = opts.memory ? opts.memory.statements || [] : null;
  const seenSig = new Set();
  const ws = [...(opts.witnesses || []), ...(mem || [])].filter(w => w && !seenSig.has(w.sig) && seenSig.add(w.sig));
  const pins = [...(opts.witnessPins || []), ...(opts.witnessPin ? [opts.witnessPin] : [])];
  res.witnessed = [];
  const seenKeys = new Set();
  let maxCount = 0, maxLag = 0;
  for (const w of ws) {
    const { sig, ...st } = w;
    if (st.v !== WITNESS_FORMAT) { fail("WITNESS", "witness statement has the wrong format"); break; }
    if (pins.length && !pins.includes(st.witness_key)) { fail("WITNESS", "witness statement signed by an unpinned witness key"); break; }
    if (st.recorder_key !== pub) { fail("WITNESS", "witness statement names another recorder key"); break; }
    if (!c.verify(st.witness_key, canon(st), sig)) { fail("WITNESS", "witness signature does not verify"); break; }
    const covered = lines[st.count - 1];
    if (!covered) { fail("WITNESS", "the witness saw " + st.count + " lines for this session, and this record has only " + lines.length); break; }
    if (covered.hash !== st.head) {
      fail("WITNESS", "the witness saw " + st.count + " lines ending in " + st.head.slice(0, 12) + ", and this record no longer has that"); break;
    }
    const lag = (Date.parse(st.witnessed_at) - Date.parse(covered.t)) / 1000;
    if (opts.maxLagSec !== undefined && !(lag <= opts.maxLagSec)) {
      fail("WITNESS", "line " + (st.count - 1) + " was witnessed " + Math.round(lag) + " s after it was written, more than the " + opts.maxLagSec + " s allowed"); break;
    }
    if (lag > maxLag) maxLag = lag;
    seenKeys.add(st.witness_key);
    if (st.count > maxCount) maxCount = st.count;
    res.witnessed.push({ count: st.count, at: st.witnessed_at, by: st.witness_key, lag_s: Math.round(lag * 10) / 10 });
  }
  if (mem) res.witness_memory = { remembered: mem.length, max_count: mem.reduce((a, w) => Math.max(a, w.count || 0), 0), from: opts.memory.from };
  res.witness_coverage = { lines_witnessed: maxCount, entries: lines.length, unwitnessed_tail: lines.length - maxCount, witnesses: seenKeys.size, max_lag_s: Math.round(maxLag * 10) / 10 };
  if (res.gates.WITNESS !== "FAIL") {
    if (mem && !mem.length && opts.requireMemory) fail("WITNESS", "the witness has no memory of this session");
    else if (!ws.length) { if (opts.requireWitness || opts.minWitnesses) fail("WITNESS", "no witness statements were supplied, and this check requires them"); else res.gates.WITNESS = "NONE"; }
    else if (opts.minWitnesses && seenKeys.size < opts.minWitnesses) fail("WITNESS", "only " + seenKeys.size + " different witnesses signed, and this check requires " + opts.minWitnesses);
    else if (opts.requireFullCoverage && maxCount < lines.length) fail("WITNESS", "the last " + (lines.length - maxCount) + " lines were never witnessed");
    else pass("WITNESS");
  }

  // TIMESTAMP: RFC 3161 tokens from a public timestamp authority, checked by the caller
  // (the token signature needs a CMS library). Here: each one must cover a head in this chain.
  const ts = opts.timestamps || [];
  res.timestamps = [];
  for (const t of ts) {
    const covered = lines[t.count - 1];
    if (!t.ok) { fail("TIMESTAMP", "the timestamp token for line " + (t.count - 1) + " does not verify" + (t.why ? ": " + t.why : "")); break; }
    if (!covered || covered.hash !== t.head) { fail("TIMESTAMP", "a timestamp authority saw " + t.count + " lines ending in " + String(t.head).slice(0, 12) + ", and this record no longer has that"); break; }
    if (opts.maxLagSec !== undefined && t.gen_time) {
      // RFC 3161 times are often whole seconds, so allow one second either way.
      const d = (Date.parse(t.gen_time) - Date.parse(covered.t)) / 1000;
      if (d > opts.maxLagSec + 1 || d < -1.5) { fail("TIMESTAMP", "the timestamp authority's time for line " + (t.count - 1) + " is " + Math.round(d) + " s from the time the line claims"); break; }
    }
    res.timestamps.push({ count: t.count, at: t.gen_time, tsa: t.tsa });
  }
  if (res.gates.TIMESTAMP !== "FAIL") {
    if (!ts.length) { if (opts.requireTimestamp) fail("TIMESTAMP", "no timestamp tokens were supplied, and this check requires them"); else res.gates.TIMESTAMP = "NONE"; }
    else pass("TIMESTAMP");
  }

  res.ok = !Object.values(res.gates).includes("FAIL");
  res.summary = summarize(lines);
  return res;
}

// What happened, from the record alone.
export function summarize(lines) {
  const pre = new Map(), post = new Map(), failed = new Map();
  const tools = {};
  let prompts = 0, turns = 0;
  for (const l of lines) {
    if (l.event === "UserPromptSubmit") prompts++;
    if (l.event === "Stop") turns++;
    const id = l.tool && l.tool.use_id;
    if (!id) continue;
    if (l.event === "PreToolUse") pre.set(id, l);
    if (l.event === "PostToolUse") { post.set(id, l); tools[l.tool.name] = (tools[l.tool.name] || 0) + 1; }
    if (l.event === "PostToolUseFailure") failed.set(id, l);
  }
  const noOutcome = [...pre.keys()].filter(id => !post.has(id) && !failed.has(id)).map(id => ({ seq: pre.get(id).seq, tool: pre.get(id).tool.name }));
  const s = lines[0] && lines.find(l => l.event === "SessionStart");
  const a = lines.find(l => l.event === "Admission");
  const outside = lines.filter(l => l.event === "PreToolUse" && l.scope && isOutside(l.scope.outside))
    .map(l => ({ seq: l.seq, tool: l.tool.name, ...(l.vendor ? { vendor: l.vendor } : {}), use_id: l.tool.use_id, ran: post.has(l.tool.use_id) || failed.has(l.tool.use_id), failed: failed.has(l.tool.use_id), outside: l.scope.outside }));
  const redacted = {};
  for (const l of lines) if (l.redacted) redacted[l.vendor || "(none)"] = (redacted[l.vendor || "(none)"] || 0) + 1;
  return {
    session: lines[0] && lines[0].session,
    model: s && s.model || null,
    started: lines[0] && lines[0].t,
    ended: lines[lines.length - 1] && lines[lines.length - 1].t,
    prompts, turns,
    tool_calls_asked: pre.size,
    tool_calls_completed: post.size,
    tool_calls_failed: failed.size,
    asked_without_outcome: noOutcome,
    tools_completed: tools,
    admission: a ? { scope: a.scope, labels: a.labels || null, policy_sha256: a.policy_sha256 } : null,
    outside_admission: outside,
    ...(Object.keys(redacted).length ? { redacted } : {}),
  };
}

// Answer trail. A turn's last answer is fingerprinted with the line's nonce, and the turn end lists
// the tool results whose figures the answer repeats. Given the answer text, anyone can redo both
// for every line shown in full.
export function checkAnswer(lines, text, c) {
  const stops = lines.filter(l => !l.redacted && l.answer && typeof l.nonce === "string");
  const hit = stops.find(l => c.sha256hex(l.nonce + "|" + String(text)) === l.answer.fp);
  if (!hit) return { ok: false, why: "this answer is not the one recorded at the end of any turn in this record" };
  const nums = numbersIn(text);
  const signed = new Map((hit.answer.drew_on || []).map(d => [d.seq, d]));
  const checked = [];
  for (const l of lines) {
    if (l.redacted || l.event !== "PostToolUse" || l.seq > hit.seq || !Array.isArray(l.vals)) continue;
    const matched = nums.filter(v => l.vals.includes(c.sha256hex(l.nonce + "|" + v))).length;
    const s = signed.get(l.seq);
    if ((s ? s.matched : 0) !== matched) return { ok: false, stop_seq: hit.seq, why: "the trail at line " + hit.seq + " says the answer used " + (s ? s.matched : 0) + " figures from line " + l.seq + ", and the answer and that line show " + matched };
    if (matched) checked.push({ seq: l.seq, vendor: l.vendor, matched });
  }
  return { ok: true, stop_seq: hit.seq, drew_on: hit.answer.drew_on || [], checked };
}

// Licence statement: one vendor's usage over a period, built from that vendor's disclosure copies.
export const STATEMENT_FORMAT = "hive.licence-statement/1";
export function statementBody(discs, vendor, period, c) {
  const sessions = [], usage = {}, outside = [], answers = [];
  let entitlement = null;
  for (const lines of discs) {
    const sfp = c.sha256hex(String(lines[0].session));
    const last = lines[lines.length - 1];
    sessions.push({ session_fp: sfp, count: lines.length, head: last.hash });
    const ent = lines.find(l => l.event === "Entitlement" && l.vendor === vendor && !l.redacted);
    if (ent && !entitlement) entitlement = ent.datasets;
    const ran = new Set(lines.filter(l => !l.redacted && l.event === "PostToolUse" && l.vendor === vendor).map(l => l.tool.use_id));
    for (const l of lines) {
      if (l.redacted || l.event !== "PreToolUse" || l.vendor !== vendor || !l.scope) continue;
      const out = new Set((l.scope.outside && l.scope.outside.datasets) || []);
      for (const d of l.scope.touched.datasets || []) {
        const u = usage[d] || (usage[d] = { dataset: d, asked: 0, ran: 0, outside: 0 });
        u.asked++; if (ran.has(l.tool.use_id)) u.ran++; if (out.has(d)) { u.outside++; outside.push({ session_fp: sfp, seq: l.seq, dataset: d }); }
      }
    }
    for (const l of lines) {
      if (l.redacted || !l.answer) continue;
      const mine = (l.answer.drew_on || []).filter(d => d.vendor === vendor);
      if (mine.length) answers.push({ session_fp: sfp, seq: l.seq, drew_on: mine.map(d => d.seq), figures: mine.reduce((a, d) => a + d.matched, 0) });
    }
  }
  sessions.sort((a, b) => a.session_fp < b.session_fp ? -1 : 1);
  return { v: STATEMENT_FORMAT, vendor, recorder_key: discs[0][0].public_key, period, entitlement, sessions,
    usage: Object.values(usage).sort((a, b) => a.dataset < b.dataset ? -1 : 1), outside, answers };
}
//   st: { ...statementBody, issued_at, sig, accepted?: { vendor_key, accepted_at, sig } }
//   opts: { recorderPin, vendorPin, witnessPin, memory: { [session_fp]: statements }, witnessSessions: [{ session_fp, count, last_at }] }
export function checkStatement(st, discs, c, opts = {}) {
  const no = (step, why) => ({ ok: false, step, why });
  if (!st || st.v !== STATEMENT_FORMAT) return no("FORMAT", "not a " + STATEMENT_FORMAT);
  const { sig, accepted, issued_at, ...b } = st;
  if (opts.recorderPin && st.recorder_key !== opts.recorderPin) return no("SIGNATURE", "the statement names a recorder key other than the pinned one");
  if (!c.verify(st.recorder_key, canon({ ...b, issued_at }), sig)) return no("SIGNATURE", "the statement's signature does not verify against the recorder key");
  for (const lines of discs) {
    const sfp = c.sha256hex(String(lines[0].session));
    const r = verifyRecord(lines, c, { pin: st.recorder_key, allowRedacted: true, discloseFor: st.vendor, witnessPin: opts.witnessPin, memory: { statements: (opts.memory || {})[sfp] || [], from: opts.from }, requireMemory: true });
    if (!r.ok) return no("RECORD", "session " + sfp.slice(0, 12) + ": " + r.first_failure.gate + ", " + r.first_failure.why);
  }
  const want = statementBody(discs, st.vendor, st.period, c);
  if (opts.witnessSessions) {
    const from = Date.parse(st.period.from), to = Date.parse(st.period.to);
    for (const w of opts.witnessSessions) {
      const t = Date.parse(w.last_at);
      if (!(t >= from && t <= to)) continue;
      const s = st.sessions.find(x => x.session_fp === w.session_fp);
      if (!s) return no("COMPLETE", "the witness saw session " + w.session_fp.slice(0, 12) + " (" + w.count + " lines) in this period, and the statement leaves it out");
      if (s.count < w.count) return no("COMPLETE", "the witness saw " + w.count + " lines for session " + w.session_fp.slice(0, 12) + ", and the statement covers " + s.count);
    }
  }
  for (const k of ["sessions", "entitlement", "usage", "outside", "answers"]) {
    if (canon(want[k]) !== canon(b[k])) return no("USAGE", "the statement's " + k + " does not match what the records show");
  }
  let acc = null;
  if (accepted) {
    const ok = c.verify(accepted.vendor_key, canon({ statement_sha256: c.sha256hex(canon({ ...b, issued_at, sig })), accepted_at: accepted.accepted_at }), accepted.sig);
    if (!ok || (opts.vendorPin && accepted.vendor_key !== opts.vendorPin)) return no("ACCEPTED", "the vendor's acceptance does not match this statement");
    acc = accepted.accepted_at;
  }
  const tot = want.usage.reduce((a, u) => ({ asked: a.asked + u.asked, outside: a.outside + u.outside }), { asked: 0, outside: 0 });
  return { ok: true, vendor: st.vendor, sessions: want.sessions.length, ...tot, answers: want.answers.length, accepted_at: acc };
}

// Delivery match. The vendor's own server keeps a signed, chained log of what it delivered, one log per
// customer, witnessed like a record. Each delivery carries a random id; the firm's recorder keeps a
// fingerprint of that id on the result line. Matching the two shows pulls the recorder never saw and
// pulls the record claims that the vendor never served. Neither side can do this from its own log.
export const DELIVERY_FORMAT = "hive.vendor-delivery/1";
export const MATCH_FORMAT = "hive.delivery-match/1";
export const DELIVERY_ID = /\\?"delivery\\?"\s*:\s*\\?"(dl-[a-z]{24})\\?"/;
//   opts: { vendorPin, witnessPin, memory: [statements fetched from the witness for this log], requireMemory }
export function checkDeliveries(vlog, c, opts = {}) {
  const no = (step, why) => ({ ok: false, step, why });
  if (!Array.isArray(vlog) || !vlog.length) return no("FORMAT", "the delivery log is empty");
  const logFp = vlog[0].log, key = opts.vendorPin;
  let prev = "0".repeat(64);
  for (let i = 0; i < vlog.length; i++) {
    const { hash, sig, ...b } = vlog[i];
    if (b.v !== DELIVERY_FORMAT || b.log !== logFp) return no("FORMAT", "delivery " + i + " is not a " + DELIVERY_FORMAT + " line of this log");
    if (b.seq !== i || b.prev !== prev) return no("CHAIN", "expected delivery " + i + " after " + prev.slice(0, 12) + ", found delivery " + b.seq);
    if (c.sha256hex(canon(b)) !== hash) return no("HASH", "delivery " + i + " changed after it was signed");
    if (!key || !c.verify(key, canon(b), sig)) return no("SIGNATURE", "delivery " + i + " is not signed by the pinned vendor key");
    prev = hash;
  }
  const mem = opts.memory || [];
  if (!mem.length && opts.requireMemory) return no("WITNESS", "the witness has no memory of this delivery log");
  let max = 0;
  for (const w of mem) {
    const { sig, ...st } = w;
    if (st.v !== WITNESS_FORMAT || (opts.witnessPin && st.witness_key !== opts.witnessPin) || st.recorder_key !== key || st.session_fp !== logFp) return no("WITNESS", "a witness statement does not belong to this log");
    if (!c.verify(st.witness_key, canon(st), sig)) return no("WITNESS", "witness signature does not verify");
    const covered = vlog[st.count - 1];
    if (!covered) return no("WITNESS", "the witness saw " + st.count + " deliveries in this log, and this copy has only " + vlog.length);
    if (covered.hash !== st.head) return no("WITNESS", "the witness saw " + st.count + " deliveries ending in " + st.head.slice(0, 12) + ", and this log no longer has that");
    max = Math.max(max, st.count);
  }
  if (mem.length && max < vlog.length) return no("WITNESS", "the last " + (vlog.length - max) + " deliveries in this log were never witnessed");
  return { ok: true, deliveries: vlog.length, log_fp: logFp, head: prev, witnessed: max };
}
export function matchDeliveries(discs, vlog, vendor, period, c) {
  const inP = t => !period || (Date.parse(t) >= Date.parse(period.from) && Date.parse(t) <= Date.parse(period.to));
  const byFp = new Map(vlog.map(d => [d.delivery_fp, d]));
  const used = new Set(), matches = [], unmatched = [];
  for (const lines of discs) {
    const sfp = c.sha256hex(String(lines[0].session));
    const pre = new Map(lines.filter(l => !l.redacted && l.event === "PreToolUse" && l.tool).map(l => [l.tool.use_id, l]));
    for (const l of lines) {
      if (l.redacted || l.event !== "PostToolUse" || l.vendor !== vendor) continue;
      const d = l.delivery_fp && byFp.get(l.delivery_fp);
      if (!l.delivery_fp) { unmatched.push({ session_fp: sfp, seq: l.seq, why: "the result carries no delivery id" }); continue; }
      if (!d) { unmatched.push({ session_fp: sfp, seq: l.seq, why: "the vendor's log has no such delivery" }); continue; }
      if (used.has(d.delivery_fp)) { unmatched.push({ session_fp: sfp, seq: l.seq, why: "delivery " + d.seq + " is already matched to another line" }); continue; }
      used.add(d.delivery_fp);
      const p = pre.get(l.tool.use_id), asked = [...((p && p.scope && p.scope.touched.datasets) || [])].sort(), got = [...d.datasets].sort();
      if (canon(asked) !== canon(got)) { unmatched.push({ session_fp: sfp, seq: l.seq, why: "the record asked for " + (asked.join(", ") || "nothing") + ", and the vendor delivered " + got.join(", ") }); continue; }
      matches.push({ session_fp: sfp, seq: l.seq, delivery_seq: d.seq, datasets: got });
    }
  }
  const unrecorded = vlog.filter(d => !used.has(d.delivery_fp) && inP(d.t)).map(d => ({ delivery_seq: d.seq, t: d.t, tool: d.tool, datasets: d.datasets }));
  return { matches, unrecorded, unmatched };
}
export function matchBody(discs, vlog, vendor, period, c) {
  const last = vlog[vlog.length - 1];
  const sessions = discs.map(L => ({ session_fp: c.sha256hex(String(L[0].session)), count: L.length, head: L[L.length - 1].hash })).sort((a, b) => a.session_fp < b.session_fp ? -1 : 1);
  return { v: MATCH_FORMAT, vendor, customer: vlog[0].customer, recorder_key: discs[0][0].public_key, period, sessions,
    log: { log_fp: vlog[0].log, count: vlog.length, head: last.hash }, ...matchDeliveries(discs, vlog, vendor, period, c) };
}
//   m: { ...matchBody, issued_at, vendor_key, sig, accepted?: { recorder_key, accepted_at, sig } }
//   opts: { recorderPin, vendorPin, witnessPin, memory: { [session_fp]: statements }, logMemory: statements, witnessSessions }
export function checkMatch(m, discs, vlog, c, opts = {}) {
  const no = (step, why) => ({ ok: false, step, why });
  if (!m || m.v !== MATCH_FORMAT) return no("FORMAT", "not a " + MATCH_FORMAT);
  const { sig, accepted, ...b } = m;
  if (opts.vendorPin && m.vendor_key !== opts.vendorPin) return no("SIGNATURE", "the match names a vendor key other than the pinned one");
  if (!c.verify(m.vendor_key, canon(b), sig)) return no("SIGNATURE", "the match is not signed by the vendor key");
  for (const lines of discs) {
    const sfp = c.sha256hex(String(lines[0].session));
    const r = verifyRecord(lines, c, { pin: opts.recorderPin || m.recorder_key, allowRedacted: true, discloseFor: m.vendor, witnessPin: opts.witnessPin, memory: { statements: (opts.memory || {})[sfp] || [] }, requireMemory: true });
    if (!r.ok) return no("RECORD", "session " + sfp.slice(0, 12) + ": " + r.first_failure.gate + ", " + r.first_failure.why);
  }
  const d = checkDeliveries(vlog, c, { vendorPin: m.vendor_key, witnessPin: opts.witnessPin, memory: opts.logMemory || [], requireMemory: true });
  if (!d.ok) return no("DELIVERIES", d.step + ", " + d.why);
  if (opts.witnessSessions) {
    const from = Date.parse(m.period.from), to = Date.parse(m.period.to);
    for (const w of opts.witnessSessions) {
      const t = Date.parse(w.last_at);
      if (!(t >= from && t <= to)) continue;
      const s = m.sessions.find(x => x.session_fp === w.session_fp);
      if (!s) return no("COMPLETE", "the witness saw session " + w.session_fp.slice(0, 12) + " (" + w.count + " lines) in this period, and the match leaves it out");
      if (s.count < w.count) return no("COMPLETE", "the witness saw " + w.count + " lines for session " + w.session_fp.slice(0, 12) + ", and the match covers " + s.count);
    }
  }
  const want = matchBody(discs, vlog, m.vendor, m.period, c);
  for (const k of ["sessions", "log", "matches", "unrecorded", "unmatched"]) if (canon(want[k]) !== canon(b[k])) return no("MATCH", "the match's " + k + " does not agree with the two logs");
  let acc = null;
  if (accepted) {
    const ok = c.verify(accepted.recorder_key, canon({ match_sha256: c.sha256hex(canon({ ...b, sig })), accepted_at: accepted.accepted_at }), accepted.sig);
    if (!ok || accepted.recorder_key !== (opts.recorderPin || m.recorder_key)) return no("ACCEPTED", "the firm's acceptance does not match this delivery match");
    acc = accepted.accepted_at;
  }
  return { ok: true, matched: want.matches.length, unrecorded: want.unrecorded.length, unmatched: want.unmatched.length, deliveries: vlog.length, accepted_at: acc };
}
// Figures an answer computed from a vendor's data. The vendor holds what it delivered (vpriv: [{ seq, delivery_id, body }]),
// so given the answer, it can tell which figures it repeats and which it derived: a sum or an average of a field.
export function checkDerived(lines, text, vlog, vpriv, vendor, c) {
  const a = checkAnswer(lines, text, c);
  if (!a.ok) return { ok: false, step: "ANSWER", why: a.why };
  const { matches } = matchDeliveries([lines], vlog, vendor, null, c);
  // Every pull of this vendor's data before the answer, not only the ones the firm's trail names:
  // a figure the agent computed can come from a result whose own figures the answer never repeats.
  const before = lines.filter(l => !l.redacted && l.answer && l.seq < a.stop_seq).reduce((x, l) => Math.max(x, l.seq), -1);
  const nums = numbersIn(text), direct = [], derived = [], seen = new Set();
  for (const mt of matches) {
    if (!(mt.seq > before && mt.seq < a.stop_seq)) continue;
    const d = vlog[mt.delivery_seq], p = (vpriv || []).find(x => x.seq === mt.delivery_seq);
    if (!p || c.sha256hex(p.delivery_id) !== d.delivery_fp || c.sha256hex(canon(p.body)) !== d.body_sha256) return { ok: false, step: "BODY", why: "the vendor's copy of delivery " + mt.delivery_seq + " is not the one its log signed" };
    const inBody = new Set(numbersIn(canon(p.body)));
    const fields = {};
    const walk = v => { if (Array.isArray(v)) { for (const o of v) if (o && typeof o === "object" && !Array.isArray(o)) for (const [k, x] of Object.entries(o)) if (typeof x === "number") (fields[k] = fields[k] || []).push(x); v.forEach(walk); } else if (v && typeof v === "object") Object.values(v).forEach(walk); };
    walk(p.body);
    for (const n of nums) {
      if (inBody.has(n) && !seen.has("d" + mt.delivery_seq + n)) { seen.add("d" + mt.delivery_seq + n); direct.push({ figure: n, delivery_seq: mt.delivery_seq, seq: mt.seq }); }
      for (const [k, xs] of Object.entries(fields)) {
        if (xs.length < 2) continue;
        const sum = xs.reduce((s, x) => s + x, 0);
        for (const [op, v] of [["sum", sum], ["average", sum / xs.length]]) if (String(Math.round(v * 1e6) / 1e6) === n) derived.push({ figure: n, op, field: k, n: xs.length, delivery_seq: mt.delivery_seq, seq: mt.seq });
      }
    }
  }
  return { ok: true, stop_seq: a.stop_seq, direct, derived };
}
