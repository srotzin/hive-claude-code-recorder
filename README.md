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

It runs seven gates (format, key pin, chain order, entry hash, signature, seal, witness), prints the first failure if there is one, and summarises the session: prompts, turns, tool calls asked, completed, failed, and asked with no outcome. A call with no outcome is one that was asked for and never ran, such as a permission denial.

## The witness

Your own key can't stop you from rewriting your own record. A witness can. At each seal, a detached process sends four fingerprints to the witness: your recorder's public key, a hash of the session id, the line count and the head hash. The witness signs "this key had a record of this many lines ending in this hash, at this time" and the statement is saved next to the record. After that, a rewritten or trimmed record fails the WITNESS gate, even if it was re-signed with your own key.

The default witness is Hive's, at `https://witness.thehiveryiq.com/v1/witness`. Hive holds that witness key, so it is a second party to you, not an independent auditor. Set `HIVE_WITNESS_URL` to use your own witness or one run by an auditor (`witness/server.mjs`, no dependencies), or to `off` to send nothing.

## Rules it keeps

- Always exits 0 and prints nothing, so it can never block, deny or change a tool call. It is not a permission check.
- Parallel hooks append in one order, using a lock per session.
- If anything goes wrong, it writes to `errors.log` in its data folder and lets Claude Code carry on.

## Tests

```
node tests/run.mjs
```

The suite runs the real hook script once per event, the way Claude Code does, using the payload shapes from Claude Code's hooks reference. It checks exit codes and output, privacy, reveal, fail-open behaviour, 40 parallel hooks, latency, the witness round trip and 10 tamper cases. Results are in `tests/RESULTS.txt`.

`examples/claude-code-session.jsonl` is a record from a real Claude Code session, witnessed by Hive's witness.

## Open format

The record format is `hive.agent-action/1`. The spec is in `spec/SPEC.md` and the JSON Schemas are in `spec/`. Any agent runtime with before and after tool hooks can produce it.

## Limits

A record proves what the runtime reported, in what order, and that it didn't change afterwards. It does not prove an action was right or authorized, and it can't include events the runtime never reported. Lines after the last witnessed seal are protected by your key alone. Signatures are Ed25519.

MIT licensed. Hive, https://thehiveryiq.com
