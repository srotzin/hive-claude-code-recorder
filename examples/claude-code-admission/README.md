# A real Claude Code session with an admission

Recorded on October 10, 2026 with Claude Code 2.1.296 and Hive Recorder 1.1.0, installed from GitHub. `HIVE_PQ=1` was set, so every line is signed with Ed25519 and ML-DSA-65. Both seals were witnessed by Hive's live witness at witness.thehiveryiq.com.

`hive-admission.json` was in the project before the session started. It allowed Read, Edit, Glob, Grep and Bash, any path in the project, and one host: registry.npmjs.org. The recorder signed it as line 1.

The task: run the tests, fix the tax bug, run the tests again, then look up a dataset on huggingface.co with curl. Claude Code's own permissions allowed curl. The admission did not allow huggingface.co.

Line 8 is the call. It was signed before it ran, with `huggingface.co` in `scope.outside.hosts`. The connection failed in the test environment (curl exit 7), and line 9 records the failure.

Check it, pinning the recorder key, the witness key and the policy:

```
node ../../plugins/hive-recorder/scripts/verify.mjs session.jsonl --key key.json --witness-key FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE --admission hive-admission.json
```

It exits 3: every gate passes, and one call fell outside the admission.

Reveal what line 8 asked to run:

```
node ../../plugins/hive-recorder/scripts/verify.mjs reveal session.jsonl --seq 8 --field input --value escape-call-input.json --fingerprint-key demo-fingerprint.key
```

`demo-fingerprint.key` is published only because this was a throwaway demo install.

`tamper/` holds 12 changed copies, built by `tests/admission-tamper.mjs` with the recorder's own keys where that makes the forgery stronger. All 12 are rejected at the gate in `tamper/MANIFEST.json`.
