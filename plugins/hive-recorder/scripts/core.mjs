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
export function body(line) {
  const { hash, sig, ...rest } = line;
  return rest;
}

export const GATES = ["FORMAT", "KEY_PIN", "CHAIN_ORDER", "ENTRY_HASH", "SIGNATURE", "SEAL", "WITNESS"];

// Verify one session record.
//   lines:    array of parsed JSON lines
//   c:        { sha256hex(str) -> hex, verify(pubB64url, msgStr, sigB64url) -> bool }
//   opts:     { pin: public key (b64url) expected, witnesses: [statements], witnessPin: b64url }
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

  // SEAL: every Seal line must cover exactly the lines before it.
  const seals = lines.filter(l => l.event === "Seal");
  for (const s of seals) {
    const before = lines[s.seq - 1];
    if (s.count !== s.seq || !before || s.head !== before.hash) { fail("SEAL", "seal at line " + s.seq + " does not match the lines before it"); break; }
  }
  pass("SEAL");
  const last = lines[lines.length - 1];
  res.sealed = last.event === "Seal";
  res.open_tail = res.sealed ? 0 : lines.length - 1 - (seals.length ? seals[seals.length - 1].seq : 0);

  // WITNESS: each statement must sign a head that is in this chain at that count.
  const ws = opts.witnesses || [];
  res.witnessed = [];
  for (const w of ws) {
    const { sig, ...st } = w;
    if (st.v !== WITNESS_FORMAT) { fail("WITNESS", "witness statement has the wrong format"); break; }
    if (opts.witnessPin && st.witness_key !== opts.witnessPin) { fail("WITNESS", "witness statement signed by an unpinned witness key"); break; }
    if (st.recorder_key !== pub) { fail("WITNESS", "witness statement names another recorder key"); break; }
    if (!c.verify(st.witness_key, canon(st), sig)) { fail("WITNESS", "witness signature does not verify"); break; }
    const covered = lines[st.count - 1];
    if (!covered || covered.hash !== st.head) {
      fail("WITNESS", "the witness saw " + st.count + " lines ending in " + st.head.slice(0, 12) + ", and this record no longer has that"); break;
    }
    res.witnessed.push({ count: st.count, at: st.witnessed_at });
  }
  if (ws.length) pass("WITNESS"); else res.gates.WITNESS = "NONE";

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
  };
}
