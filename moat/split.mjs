// Derived-figure split across vendors. One figure in an agent's answer, built from two vendors' deliveries, credited to
// each vendor without showing either vendor the other's name, delivery or value.
//
// The firm builds one statement and registers it on the public log. The statement names no vendor and carries no value:
// only the session, the answer's fingerprint, the figure, the operation, and for each input the step it came from, the
// delivery fingerprint, and the salted value fingerprint the recorder kept at that step. Each vendor then gets a private
// opening for its own input only (the value), and checks everything against its own delivery log and its own copy of
// the session. An auditor the firm gives every opening can check the arithmetic.
//
// Why a third party: each vendor checks the same registered statement, on a log neither vendor runs. A vendor's own log
// can carry its half; it cannot be the place the other vendor checks.
import { canon, numbersIn, verifyRecord } from "../plugins/hive-recorder/scripts/core.mjs";

export const OPS = {
  "x / y": (x, y) => x / y, "x * y": (x, y) => x * y, "x - y": (x, y) => x - y, "x + y": (x, y) => x + y,
};
const decimals = s => (String(s).split(".")[1] || "").length;
const sig = s => String(s).replace(/[^0-9]/g, "").replace(/^0+/, "").length;
// The figure as written shows v: same value rounded to the figure's own decimals, and at least 3 significant digits.
export const shows = (fig, v) => sig(fig) >= 3 && Number.isFinite(v) && Math.abs(Number(v.toFixed(decimals(fig))) - Number(fig)) < 1e-9;

// Firm side. lines: the full session record. received: { [step_seq]: [numbers the agent received at that step, as text] }.
export function findSplits(lines, answer, received, c) {
  const posts = lines.filter(l => l.event === "PostToolUse" && l.vendor && l.delivery_fp && Array.isArray(l.vals));
  const vf = (l, v) => c.sha256hex(l.nonce + "|" + v);
  const out = [];
  for (const fig of numbersIn(answer)) for (const a of posts) for (const b of posts) {
    if (a.vendor === b.vendor) continue;
    for (const x of received[a.seq] || []) for (const y of received[b.seq] || []) {
      if (!a.vals.includes(vf(a, x)) || !b.vals.includes(vf(b, y))) continue;
      for (const [op, f] of Object.entries(OPS)) if (shows(fig, f(Number(x), Number(y))))
        out.push({ figure: fig, op, inputs: [{ l: a, v: x }, { l: b, v: y }] });
    }
  }
  return out;
}

export function splitStatement(lines, answer, found, c) {
  const stop = [...lines].reverse().find(l => l.event === "Stop"), seal = [...lines].reverse().find(l => l.event === "Seal");
  const body = {
    kind: "hive.derived-split/1", recorder_key: lines[0].public_key, session_fp: c.sha256hex(String(lines[0].session)),
    session_head: seal.head, session_count: seal.count, answer_fp: stop.answer.fp, figure: found.figure, op: found.op,
    inputs: found.inputs.map(({ l, v }) => ({ step_seq: l.seq, delivery_fp: l.delivery_fp, val_fp: c.sha256hex(l.nonce + "|" + v) })),
    note: "Names no vendor and carries no value. Each vendor gets an opening for its own input only.",
  };
  const split_sha256 = c.sha256hex(canon(body));
  const openings = found.inputs.map(({ l, v }, i) => ({ vendor: l.vendor, opening: { split_sha256, input: i, value: String(v) } }));
  return { statement: body, split_sha256, openings };
}

const no = (step, why) => ({ ok: false, step, why });

// Vendor side. copy: this vendor's copy of the session (discloseFor). vlog: its own delivery log. kept: what it kept of
// each delivery ({ delivery_fp, body }). The statement must be the registered one (check the receipt separately).
export function checkMyInput(st, op, copy, vlog, kept, c) {
  if (st.kind !== "hive.derived-split/1") return no("KIND", "not a derived-figure split");
  const vr = verifyRecord(copy, c, { pin: st.recorder_key, allowRedacted: true, discloseFor: vlog[0] && vlog[0].vendor }); if (!vr.ok) return no("RECORD", "this vendor's copy of the session does not verify: " + (vr.first_failure ? vr.first_failure.gate + ", " + vr.first_failure.why : "unknown"));
  if (c.sha256hex(canon(st)) !== op.split_sha256) return no("OPENING", "the opening is for a different statement");
  const inp = st.inputs[op.input]; if (!inp) return no("OPENING", "the opening names no input of this statement");
  const d = vlog.find(x => x.delivery_fp === inp.delivery_fp); if (!d) return no("DELIVERY", "the input's delivery is not in this vendor's log");
  const k = kept.find(x => x.delivery_fp === inp.delivery_fp); if (!k) return no("DELIVERY", "this vendor kept no body for that delivery");
  if (!numbersIn(JSON.stringify(k.body)).includes(op.value)) return no("VALUE", "the opened value is not in what this vendor delivered");
  if (c.sha256hex(String(copy[0].session)) !== st.session_fp || copy[0].public_key !== st.recorder_key) return no("SESSION", "this vendor's copy is of a different session");
  const step = copy.find(l => l.seq === inp.step_seq);
  if (!step || step.redacted || step.delivery_fp !== inp.delivery_fp) return no("STEP", "the named step in this vendor's copy is not that delivery");
  if (c.sha256hex(step.nonce + "|" + op.value) !== inp.val_fp || !step.vals.includes(inp.val_fp)) return no("VALUE", "the value fingerprint at that step does not open to the value");
  const stop = [...copy].reverse().find(l => l.event === "Stop"), seal = [...copy].reverse().find(l => l.event === "Seal");
  if (!stop || stop.answer.fp !== st.answer_fp) return no("ANSWER", "the statement's answer is not the answer in this session");
  if (!seal || seal.head !== st.session_head || seal.count !== st.session_count) return no("SESSION", "the statement names a different end of the session");
  const others = st.inputs.filter((_, i) => i !== op.input);
  if (others.some(o => vlog.some(x => x.delivery_fp === o.delivery_fp))) return no("SPLIT", "another input is also this vendor's delivery, so the figure is not a cross-vendor split");
  if (others.some(o => { const s = copy.find(l => l.seq === o.step_seq); return !s || !s.redacted; })) return no("SPLIT", "the other input is not a step this vendor's copy keeps hidden");
  return { ok: true, figure: st.figure, op: st.op, my_input: op.input === 0 ? "x" : "y", my_value: op.value, my_delivery_seq: d.seq, other_inputs: others.length };
}

// Auditor with every opening: the figure is the operation over the opened values.
export function checkArithmetic(st, openings, c) {
  const sh = c.sha256hex(canon(st)); if (openings.some(o => o.split_sha256 !== sh)) return no("OPENING", "an opening is for a different statement");
  const v = st.inputs.map((_, i) => openings.find(o => o.input === i)); if (v.some(x => !x)) return no("OPENING", "an input has no opening");
  const f = OPS[st.op]; if (!f) return no("OP", "unknown operation");
  if (!shows(st.figure, f(Number(v[0].value), Number(v[1].value)))) return no("ARITHMETIC", "the figure is not " + st.op + " over the opened values");
  return { ok: true };
}
