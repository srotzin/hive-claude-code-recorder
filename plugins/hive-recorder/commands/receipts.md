---
description: Check this machine's Hive records and show what the agent did, from the signed record alone
---
Run this shell command and show me its output exactly, then explain it in two or three plain sentences:

```
node "${CLAUDE_PLUGIN_ROOT}/scripts/verify.mjs" $(ls -t "${CLAUDE_PLUGIN_DATA}/records/"*.jsonl 2>/dev/null | grep -v witness | head -5)
```

Do not change, move or delete any file in the records folder. If no records exist yet, say so.
