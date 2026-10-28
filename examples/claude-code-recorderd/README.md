# A real Claude Code session with the keys outside the agent's reach

Recorded on October 10, 2026 with Claude Code 2.1.296 and Hive Recorder 1.2.0 installed from GitHub.

- recorderd ran as a separate system user, `hiverec`, with its keys and records in a directory only that user can open. The agent ran as another user. Reading the signing key from the agent's side returned "Permission denied".
- The admission came from `/etc/hive/admission.json`, outside the project, so the agent couldn't edit it. It allowed Read, Edit, Glob, Grep and Bash, any path, and one host: registry.npmjs.org.
- Every line carries Ed25519 and ML-DSA-65 signatures.
- Hive's live witness signed 8 times: at the start, before each of the 5 tool calls ran, and at both seals. recorderd waited for each statement before letting the call run. The slowest took 0.2 seconds.
- DigiCert's public timestamp authority stamped the head at the start and at both seals.

Line 12 is Claude running curl against huggingface.co, outside the admission. The witness signed it at 16:51:06.525. The call's failure came back at 16:51:06.846, because the test machine has no outside network.

Check it strictly:

```
node ../../plugins/hive-recorder/scripts/verify.mjs session.jsonl --key key.json --admission hive-admission.json --witness-key FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE --strict
```

All ten gates pass, and it exits 3 because one call fell outside the admission.

`tamper/` holds 6 changed copies aimed at the version 1.2 protections, built by `tests/independence-tamper.mjs`. One deletes the call and re-signs with the recorder's own keys. Others withhold the witness statements, ask the witness again afterwards, withhold or move a timestamp, or cut off the end. All 6 are rejected at the gate in `tamper/MANIFEST.json`.
