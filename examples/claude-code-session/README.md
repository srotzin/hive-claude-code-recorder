# A real Claude Code session

Recorded on October 10, 2026 with Claude Code 2.1.296 and this plugin installed from GitHub with `claude plugin marketplace add srotzin/hive-claude-code-recorder`. Both seals were witnessed by Hive's live witness at witness.thehiveryiq.com.

The task: run the tests in a small billing project, fix the tax bug, run the tests again, then tell CI with a curl call. The session was started with `--allowedTools Read Edit Glob Grep "Bash(node test.js)"`, so Claude Code denied the curl call.

`claude-code-output.json` is Claude Code's own output for the session. Its `permission_denials` list names one call, `toolu_01KjXtjDwNcr1TbBfmXekEzp`. The record shows the same call at line 9: asked for, with no outcome.

Check it:

```
node ../../plugins/hive-recorder/scripts/verify.mjs session.jsonl --key key.json --witness-key FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE
```

Reveal the denied call's input and check it against its fingerprint:

```
node ../../plugins/hive-recorder/scripts/verify.mjs reveal session.jsonl --seq 9 --field input --value denied-call-input.json --fingerprint-key demo-fingerprint.key
```

`demo-fingerprint.key` is published only because this was a throwaway demo install. On a real machine the fingerprint key never leaves it.

`tamper/` holds 12 changed copies of this record. Each one is rejected, and `tamper/MANIFEST.json` lists the gate each should fail at.
