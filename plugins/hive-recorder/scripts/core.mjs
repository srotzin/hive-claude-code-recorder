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

export const GATES = ["FORMAT", "KEY_PIN", "CHAIN_ORDER", "ENTRY_HASH", "SIGNATURE", "PQ_SIGNATURE", "SEAL", "ADMISSION", "WITNESS", "TIMESTAMP"];

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
//               requireMemory: the witness must remember this session }
export function verifyRecord(lines, c, opts = {}) {
  const res = { ok: false, gates: {}, first_failure: null, entries: lines.length, summary: null };
  const fail = (g, why) => { if (!res.first_failure) res.first_failure = { gate: g, why }; res.gates[g] = "FAIL"; };
  const pass = g => { if (res.gates[g] !== "FAIL") res.gates[g] = "PASS"; };
  if (!Array.isArray(lines) || lines.length === 0) { fail("FORMAT", "empty record"); return res; }

  // FORMAT
  const start = lines[0];
  for (const [i, l] of lines.entries()) {
    if (!l || l.v !== FORMAT || typeof l.seq !== "number" || typeof l.hash !== "string" || typeof l.sig !== "string" || typeof l.event !== "string") { fail("FORMAT", "line " + i + " is not " + FORMAT); return res; }
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
    const b = canon(body(l));
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
        if (typeof l.sig_pq !== "string" || !c.verifyPq(start.pq_public_key, canon(body(l)), l.sig_pq)) { fail("PQ_SIGNATURE", "line " + i + " ML-DSA-65 signature is missing or does not verify"); break; }
      }
      pass("PQ_SIGNATURE");
    }
  } else res.gates.PQ_SIGNATURE = "NONE";

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
      for (const l of lines) {
        if (l.event !== "PreToolUse") continue;
        if (!l.scope || !l.scope.touched) { fail("ADMISSION", "line " + l.seq + " has no scope check"); break; }
        const want = checkScope(a.scope, l.tool.name, l.scope.touched);
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
    .map(l => ({ seq: l.seq, tool: l.tool.name, use_id: l.tool.use_id, ran: post.has(l.tool.use_id) || failed.has(l.tool.use_id), failed: failed.has(l.tool.use_id), outside: l.scope.outside }));
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
  };
}
