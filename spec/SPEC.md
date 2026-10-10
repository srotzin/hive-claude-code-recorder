# hive.agent-action/1

An open format for a signed, tamper-evident record of what an AI agent did. Version 1.2.0, October 10, 2026. Version 1.1 adds the signed admission, the scope check and an optional ML-DSA-65 signature. Every 1.0 record is a valid 1.1 record.

The first producer is the Hive Recorder plugin for Claude Code. The format does not depend on Claude Code. Any agent runtime that can call a hook before and after a tool runs can produce it.

## What a record proves, and what it does not

A record proves which events the agent runtime reported, in what order and at what time, and that none of those lines changed, moved or disappeared afterwards. With a witness statement, it also proves that the record already existed in that exact form at the witnessed time.

With an admission, it also proves what the session was allowed to touch, signed before anything happened, and which calls reached outside that. It does not say why, or whether reaching outside was wrong.

A record does not prove that an action was right, safe or authorized. It does not prove that the runtime reported every event. It holds no content, so on its own it does not show what a prompt or a tool call said. The owner can reveal any single value later and anyone can check it against its fingerprint.

## Files

One record per agent session, as JSON Lines: one JSON object per line, UTF-8, newline terminated.

- `<session>.jsonl`: the record.
- `<session>.witness.jsonl`: zero or more witness statements for that record.
- `key.json`: the recorder's public key, given to whoever will check the record.

## Line fields

Every line has these fields.

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | string | Always `hive.agent-action/1`. |
| `seq` | integer | 0 for the first line, then +1 per line. |
| `prev` | hex string | `hash` of the line before. 64 zeros on line 0. |
| `t` | string | Recorder clock, ISO 8601 UTC with milliseconds. |
| `key` | string | `key_id` of the recorder key that signed this line. |
| `event` | string | What happened. See the event table. |
| `session` | string | The runtime's session id. |
| `hash` | hex string | SHA-256 of the canonical body. |
| `sig` | base64url | Ed25519 signature over the canonical body. |
| `sig_pq` | base64url | Optional. ML-DSA-65 (FIPS 204) signature over the same canonical body. Present on every line when `RecorderKey` names a `pq_public_key`. |

The body is the line without `hash`, `sig` and `sig_pq`.

Optional fields, present when the event carries them:

| Field | Meaning |
| --- | --- |
| `tool.name`, `tool.use_id`, `tool.mcp_server` | Tool name, the runtime's call id, and the MCP server name for MCP tools. |
| `fp.<field>` | Keyed fingerprint of one value. See Fingerprints. |
| `bytes.<field>` | Size in bytes of the canonical form of the same value. |
| `fp_cwd` | Keyed fingerprint of the working directory. |
| `prompt_id`, `permission_mode`, `duration_ms`, `interrupted` | Copied from the runtime. |
| `agent.id`, `agent.type` | Present when the event came from a subagent. |
| `source`, `model` | On `SessionStart`. |
| `reason` | On `SessionEnd`. |
| `pq_alg`, `pq_public_key` | On `RecorderKey`, when the recorder also signs with ML-DSA-65. `pq_public_key` is the 1,952 byte public key, base64url. |
| `scope` | On `Admission`: `{ tools, paths, hosts }`, each a sorted list of glob patterns. On `PreToolUse` when the record has an admission: `{ touched: { paths, hosts }, outside: { tool, paths, hosts } }`. |
| `labels`, `fp_purpose`, `policy_sha256` | On `Admission`. Free-form labels from the policy (for example sandbox or tenant), a keyed fingerprint of the stated purpose, and SHA-256 of the canonical policy file. |

## Events

| `event` | Written when | Fingerprinted fields |
| --- | --- | --- |
| `RecorderKey` | First line of every record. Publishes `public_key` (base64url, 32 bytes), `key_id` and `recorder`. | none |
| `Admission` | Line 1, only when an admission policy was supplied. What the session may touch. | `purpose` |
| `SessionStart` | The session starts or resumes. | none |
| `UserPromptSubmit` | The user sends a prompt. | `prompt` |
| `PreToolUse` | The agent asks to run a tool. | `input` |
| `PostToolUse` | The tool finished. | `input`, `response` |
| `PostToolUseFailure` | The tool failed. | `input`, `error` |
| `Stop`, `SubagentStop` | A turn ends. | `last_message` |
| `SessionEnd` | The session ends. | none |
| `Seal` | Right after `Stop` and `SessionEnd`. Carries `count` and `head`. | none |
| any other | Another runtime event. | `event_fields` |

A `PreToolUse` with no matching `PostToolUse` or `PostToolUseFailure` for the same `tool.use_id` means the call was asked for and did not run to an outcome the runtime reported. In Claude Code that covers permission denials and cancelled calls.

## Admission and scope

Whoever starts the agent (a sandbox orchestrator, a CI job, a person) can supply an admission policy. The Claude Code recorder reads it once, when the record starts, from `HIVE_ADMISSION` or `<project>/.claude/hive-admission.json`:

```
{ "purpose": "Fix the invoice tax bug using only this repository.",
  "tools": ["Read", "Edit", "Bash", "mcp__github__*"],
  "paths": ["**"],
  "hosts": ["registry.npmjs.org", "*.github.com"],
  "labels": { "sandbox": "eval-7f3a" } }
```

The recorder signs it as line 1, before the first tool call. For every `PreToolUse` after that, it records what the call touches and what fell outside the admission:

- `touched.paths`: `file_path`, `notebook_path` and `path` from the tool input. Paths inside the project are relative to it; anything else is absolute. `Glob` and `Grep` with no path touch `.`.
- `touched.hosts`: hostnames from URLs, `git@host:`, `ssh`, `sftp`, `nc`, `telnet`, `scp` and `rsync` in a Bash command, and from `url`, `uri`, `endpoint`, `base_url`, `host` and `hostname` in any tool input.
- `outside`: `checkScope()` in `core.mjs`. `tool` is true when no tool pattern matches the tool name. In `paths`, `**` matches anything, `*` stops at `/`, and an absolute path only matches an absolute pattern. In `hosts`, `*` stops at `.`.

The scope check reports. It never blocks the call. The checker re-runs it from the signed admission and the recorded `touched` values, so a line that hides a call outside scope is rejected, even when it is re-signed with the recorder's own keys.

With an admission, the paths and hostnames a call touches are kept in plaintext, because anyone checking the record must be able to re-run the check. These are identifiers. Prompts, tool input, tool output and file content are still fingerprints only.

## Canonical form

Canonical JSON: object keys sorted by code unit, no insignificant whitespace, arrays in order, keys with undefined values omitted, strings and numbers as `JSON.stringify` writes them. The reference implementation is `canon()` in `core.mjs`.

## Hash, signature, chain

```
body   = line without hash, sig and sig_pq
hash   = hex(SHA-256(canon(body)))
sig    = base64url(Ed25519.sign(recorder_private_key, canon(body)))
sig_pq = base64url(ML-DSA-65.sign(recorder_pq_private_key, canon(body)))   optional
```

The Claude Code recorder signs with ML-DSA-65 as well when `HIVE_PQ=1` is set as the record starts. It uses a bundled copy of @noble/post-quantum, MIT licensed.

`prev` of line n is `hash` of line n-1. Changing, removing, adding or reordering any line breaks either a hash, a signature or the `prev` link.

## Seal

A `Seal` line closes a stretch of the record:

```
count = seq of the Seal line   (the number of lines before it)
head  = hash of the line before it
```

## Fingerprints

```
fp = hex(HMAC-SHA256(fingerprint_key, canon(value)))
```

The fingerprint key is 32 random bytes created on the recorder's machine. It is separate from the signing key. Without it, a fingerprint reveals nothing, including for short, guessable values like `npm test`. With it, the owner can reveal one value and anyone can check that it is the value that was fingerprinted, without seeing any other value.

## Witness

A witness is a second party that signs a statement about a seal head. It receives exactly four fields and nothing else:

```
POST /v1/witness
{ "recorder_key": "<base64url>", "session_fp": "<hex sha256 of session id>", "count": <int>, "head": "<hex>" }
```

It returns a statement:

```
{ "v": "hive.agent-action-witness/1", "recorder_key", "session_fp", "count", "head",
  "witnessed_at": "<ISO 8601>", "witness_key": "<base64url>", "sig": "<base64url Ed25519 over canon(statement without sig)>" }
```

The statement says: this recorder key had a record of `count` lines ending in `head`, at `witnessed_at`. After that, the record's owner cannot rewrite or trim those lines, even with their own key, without the statement exposing it.

The recorder sends the seal head from a detached process after the hook has already returned, so a slow or offline witness never delays the agent. A failed send is logged locally.

## Verification gates

A checker runs these in order and reports the first failure.

| Gate | Passes when |
| --- | --- |
| `FORMAT` | Every line is a `hive.agent-action/1` line, and line 0 is `RecorderKey`. |
| `KEY_PIN` | The record's public key equals the pinned key, if one was supplied, and every line names the same `key_id`. |
| `CHAIN_ORDER` | `seq` runs 0, 1, 2 and each `prev` equals the previous `hash`. |
| `ENTRY_HASH` | Each `hash` equals SHA-256 of the canonical body. |
| `SIGNATURE` | Each `sig` verifies under the record's public key. |
| `PQ_SIGNATURE` | When `RecorderKey` names a `pq_public_key`, every line has a `sig_pq` that verifies under it. `NONE` otherwise. |
| `SEAL` | Each `Seal` has `count` equal to its `seq` and `head` equal to the previous line's `hash`. |
| `ADMISSION` | When there is an `Admission` line, it is line 1 and appears once, its `policy_sha256` and `scope` match the policy the checker was given (if any), every `PreToolUse` carries a scope check, and every recorded `outside` equals the checker's own result. `NONE` when there is no admission. |
| `WITNESS` | Each witness statement verifies under the pinned witness key, names this recorder key, and its `head` is the hash of line `count - 1` of this record. `NONE` when there are no statements. |

The reference checker exits 0 when every gate passes and nothing fell outside the admission, 3 when every gate passes and one or more calls fell outside it, and 1 when a gate fails.

## Rules for producers

1. Never block or change the agent's action. The Claude Code recorder always exits 0, prints nothing to stdout and is not a permission check.
2. Never write or send raw content. Fingerprints and byte sizes only. With an admission, touched paths and hostnames are the one exception, for the reason above.
3. Keep the signing key and the fingerprint key on the machine that records. Do not send either anywhere.
4. Append in one order per session, using a lock, because runtimes can fire hooks in parallel.

## Independence (1.2)

These additions narrow what the producer, the lab or the agent can change without being caught. None of them changes the line format.

### When the witness signs

A producer sends the current head to every witness at the start of the record, after writing each `PreToolUse` line and before the call runs, and after every seal. A witness request covers the whole record up to and including the last line written, so a seal is itself witnessed. A producer may wait for the statements before releasing the call (`HIVE_WITNESS_WAIT_MS`). It must never block or fail the call if a witness is slow or down.

### More than one witness

`HIVE_WITNESS_URL` takes a comma separated list. A checker can pin several witness keys and require statements from a minimum number of different witnesses (`--min-witnesses`). The witness is open source (`witness/server.mjs`), so the second witness can be run by an auditor, an evaluator or the other side.

### Lag

Every statement carries the witness's own time. A checker can require that each covered line was witnessed within a set number of seconds of its own time (`--max-lag`). A record rewritten later and witnessed again gets late statements and fails.

### Public timestamps (RFC 3161)

At the start and at every seal, a producer may send the head hash, and nothing else, to one or more public timestamp authorities (`HIVE_TSA_URL`, default `http://timestamp.digicert.com`). The token is stored next to the record, one JSON line each:

```
{ "v": "hive.agent-action-timestamp/1", "count": 18, "head": "<64 hex>", "tsa": "<url>", "token": "<base64 DER TimeStampResp>" }
```

The token's message imprint is SHA-256 with the head's 32 bytes as the hashed message. A checker verifies it with `openssl ts -verify -digest <head> -in <token> -CAfile <system CAs>` and checks the head is in the chain at `count`, and that the authority's time is within the lag of that line's time. No Hive key is involved in this gate.

### Service mode: keys outside the agent's reach

`recorderd.mjs` runs the recorder as a small service, under a different user, in a sidecar or on the host that starts the sandbox. The hook keeps only the fingerprint key and sends a description (event, names, fingerprints, sizes, touched paths and hosts). recorderd refuses any other field. It holds the signing keys and the record, reads the admission from a file the agent can't edit, and calls the witnesses and timestamp authorities itself. The agent can add lines through the hook. It can't change, reorder or remove one.

### Witness memory

A witness may keep every statement it signs and serve them back:

```
GET /v1/witness/statements?recorder_key=<43 base64url>&session_fp=<64 hex>
{ "format": "hive.agent-action-witness/1", "witness_key": "...", "statements": [ ...each exactly as signed... ] }
```

It stores the same four fingerprints it was sent, its own time, its key and its signature. Nothing else. A checker that asks (`--ask-witness`) checks the record against every remembered statement, not only the ones handed over. A record cut short, or rebuilt with a call removed and fresh statements obtained afterwards, fails, because the witness still holds the original heads. A session the witness has no memory of fails when memory is required.

### Strict checking

`--strict` turns on all of: statements required, every line covered, lag at most 10 seconds, a timestamp required, and the record must end with `SessionEnd` and a seal. A reviewer who wasn't there should check with `--strict`.

## Limits

- The record is only as complete as the runtime's hooks. Events the runtime does not report are not recorded.
- Someone holding the recorder key can write a new, consistent record from scratch. Witness statements catch that for every line they cover, and with witnessing before every call that is every line. In plugin mode the keys sit on the agent's machine. In service mode they don't.
- A witness without memory keeps nothing, so its statements travel with the record. A checker that requires them (`--strict`) fails a record handed over without them. A record fully rebuilt later, with fresh statements and fresh times, has to carry the time it was really rebuilt: the public timestamps' times must sit within the lag of each covered line. It is caught by anyone who knows when the session really ran, or by a witness that remembers what it signed.
- The recorder clock is the machine's clock. The witness clock is the witness's. A timestamp authority's clock is its own, and is the only one no party to the session controls.
- When Hive runs the witness, Hive holds the witness key. It is a second party to the customer, not an independent auditor. An organization can run its own witness from `witness/server.mjs`, or use one run by an auditor.
- Every line is signed with Ed25519. The ML-DSA-65 signature is optional. The witness signs with Ed25519 only.
- The scope check only sees what the tool input names. A Bash command that reads a file is not read for paths, and a host reached by a program the agent starts, or through a variable, is not seen. Covering that takes a recorder on the network boundary that writes the same records.
- The admission says what the session was allowed to touch. It is only as good as whoever wrote it, and nothing in the record shows that the policy was right.

## Versioning

A breaking change gets a new `v` value. Checkers must reject lines with a `v` they do not know.
