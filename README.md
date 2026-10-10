# Hive Recorder for Claude Code

A Claude Code plugin that signs a tamper-evident record of what the agent did: every prompt, every tool call it asked for, every tool call that ran or failed, and every turn. Someone else can check the record later, offline, without trusting whoever sent it.

It keeps fingerprints, never content. It never blocks or slows a tool call in any way you would notice. The keys are made on your machine and stay there.

## Install

```
claude plugin marketplace add srotzin/hive-claude-code-recorder
claude plugin install hive-recorder@hive
```

Or inside Claude Code: `/plugin marketplace add srotzin/hive-claude-code-recorder`, then `/plugin install hive-recorder@hive`.

Needs Node 20 or later on your PATH. Check your records any time with `/hive-recorder:receipts`.

## What it writes

One file per session in Claude Code's plugin data folder (`~/.claude/plugins/data/hive-recorder-hive/records/`). Each line is signed with Ed25519 and points to the hash of the line before it. A seal closes the record at the end of every turn and at session end.

What a line keeps: the event, the time, the tool name and call id, the MCP server name, byte sizes, duration, and a keyed fingerprint (HMAC-SHA256) of the prompt, the tool input, the tool output or the error. What a line never keeps: the prompt, the input, the output, file paths, file contents or the assistant's reply.

Because the fingerprints are keyed with a secret that stays on your machine, nobody can guess them, even for short values like `npm test`. When you need to show one value, you reveal it, and anyone can check it matches:

```
node verify.mjs reveal session.jsonl --seq 7 --field input --value value.json --fingerprint-key fingerprint.key
```

## Check a record

```
node plugins/hive-recorder/scripts/verify.mjs <session.jsonl> --key key.json --witness-key <witness key>
```

It runs nine gates (format, key pin, chain order, entry hash, signature, ML-DSA-65 signature, seal, admission, witness), prints the first failure if there is one, and summarises the session: prompts, turns, tool calls asked, completed, failed, and asked with no outcome. A call with no outcome is one that was asked for and never ran, such as a permission denial.

## Admission: what the session was allowed to touch

Whoever starts the agent can write down, before it starts, what it may touch. Put this in `.claude/hive-admission.json` in the project, or point `HIVE_ADMISSION` at it:

```
{ "purpose": "Fix the invoice tax bug using only this repository.",
  "tools": ["Read", "Edit", "Bash", "Glob", "Grep"],
  "paths": ["**"],
  "hosts": ["registry.npmjs.org"],
  "labels": { "sandbox": "eval-7f3a" } }
```

The recorder signs it as line 1, before the first tool call. Every tool call after that records the paths and hosts it touches, and which of them fell outside the admission. The checker re-runs that check itself from the signed admission, so a record that hides an out-of-scope call is rejected, even when it is re-signed with the recorder's own key.

It reports. It never blocks. With an admission, touched paths and hostnames are kept in plaintext so anyone can re-run the check. Prompts, inputs and outputs stay fingerprints. Give a reviewer the policy file and they can pin it with `--admission policy.json`.

The checker exits 0 when the record holds and everything stayed inside the admission, 3 when the record holds and something reached outside, and 1 when the record was changed.

## Optional ML-DSA-65 signature

Set `HIVE_PQ=1` and every line is also signed with ML-DSA-65 (FIPS 204), using a bundled copy of [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) (MIT). The checker verifies both signatures. It adds about 60 ms per hook. The witness still signs with Ed25519.

## The witness

Your own key can't stop you from rewriting your own record. A witness can. At each seal, a detached process sends four fingerprints to the witness: your recorder's public key, a hash of the session id, the line count and the head hash. The witness signs "this key had a record of this many lines ending in this hash, at this time" and the statement is saved next to the record. After that, a rewritten or trimmed record fails the WITNESS gate, even if it was re-signed with your own key.

The default witness is Hive's, at `https://witness.thehiveryiq.com/v1/witness`. Hive holds that witness key, so it is a second party to you, not an independent auditor. Set `HIVE_WITNESS_URL` to use your own witness or one run by an auditor (`witness/server.mjs`, no dependencies), or to `off` to send nothing.

## Independence: keys outside the agent, many witnesses, public timestamps

Version 1.2 is built so that nobody involved in a session, including Hive, has to be trusted for the record to hold.

- The witness signs at the start, before every tool call runs and at every seal. Set `HIVE_WITNESS_WAIT_MS=2500` to make sure the statement exists before the call runs.
- `HIVE_WITNESS_URL` takes several witnesses, comma separated. Run your own from `witness/server.mjs`, or have an auditor run one.
- At the start and at every seal, the head hash goes to a public timestamp authority (DigiCert by default, `HIVE_TSA_URL`). Checking it uses openssl and your system's certificates, no Hive key.
- `scripts/recorderd.mjs` runs the recorder as a service under another user. The hook keeps only the fingerprint key and sends fingerprints. The agent can add lines. It can't change or remove one, because it never holds the signing keys or the record.

```
sudo -u hiverec env HIVE_RECORDER_DIR=/var/lib/hive-recorder HIVE_ADMISSION=/etc/hive/admission.json HIVE_PQ=1 HIVE_WITNESS_WAIT_MS=2500 node scripts/recorderd.mjs
HIVE_RECORDER_URL=http://127.0.0.1:18890 claude
```

Check strictly. A reviewer who wasn't there should always use `--strict`:

```
node plugins/hive-recorder/scripts/verify.mjs session.jsonl --key key.json --admission hive-admission.json --witness-key <key> --strict
```

`examples/claude-code-recorderd/` is a real session recorded this way, with 6 tamper cases aimed at these protections.

## Rules it keeps

- Always exits 0 and prints nothing, so it can never block, deny or change a tool call. It is not a permission check.
- Parallel hooks append in one order, using a lock per session.
- If anything goes wrong, it writes to `errors.log` in its data folder and lets Claude Code carry on.

## Tests

```
node tests/run.mjs
```

The suite runs the real hook script once per event, the way Claude Code does, using the payload shapes from Claude Code's hooks reference. It checks exit codes and output, privacy, reveal, fail-open behaviour, 40 parallel hooks, latency, the witness round trip, 10 tamper cases, the admission and scope check, and the ML-DSA-65 signature. Results are in `tests/RESULTS.txt`.

`examples/claude-code-session/` is a record from a real Claude Code session, witnessed by Hive's live witness. Claude Code denied one call in that session, and the record shows it as asked for with no outcome. Its 12 tamper cases are all rejected (`node tests/real-tamper.mjs`).

`examples/claude-code-admission/` is a second real session with an admission and ML-DSA-65 signatures. Claude reached a host the admission did not allow, and the record shows it.

## Open format

The record format is `hive.agent-action/1`. The spec is in `spec/SPEC.md` and the JSON Schemas are in `spec/`. Any agent runtime with before and after tool hooks can produce it.

## Limits

A record proves what the runtime reported, in what order, and that it didn't change afterwards. It does not prove an action was right or authorized, and it can't include events the runtime never reported. In plugin mode the keys sit on the agent's machine; in service mode they don't. The witness keeps nothing yet, so a record rebuilt from scratch later, with every time faked, is caught by the public timestamps or by knowing when the session ran. The scope check only sees what a tool's input names: a host reached by a program the agent starts is not seen. Every line is signed with Ed25519; ML-DSA-65 is optional.

MIT licensed. Hive, https://thehiveryiq.com
