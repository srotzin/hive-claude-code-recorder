# Licensed data through an MCP tool, checked against the witness's memory

Recorded on October 10, 2026 with Claude Code and Hive Recorder 1.2.2, in service mode: recorderd ran as its own system user and held the keys and the record.

- The admission, read from `/etc/hive/admission-ds.json`, allowed two futures datasets, `futures.brent.*` and `futures.wti.eod`, through a market-data MCP server.
- The MCP server is a local stand-in (`market-data-standin.mjs`). Its values are made up and labelled as stand-in data in every reply.
- Claude pulled Brent settlements, inside the admission, then 5 rows of `mortgage.loan-level`, outside it. Line 8 flags the dataset. The record names the dataset and keeps none of the data.
- Hive's live witness signed before each call ran and remembers every statement. DigiCert stamped the start and both seals.

Check it without any witness statements at all, by asking the witness:

```
node ../../plugins/hive-recorder/scripts/verify.mjs session.jsonl --key key.json --admission hive-admission.json --witness /none --ask-witness --strict --witness-key FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE
```

`tamper/` holds 3 changed copies, built by `tests/memory-tamper.mjs` and handed over with no witness statements: the pull deleted and re-signed with the recorder's own keys, the pull relabelled as an allowed dataset and re-signed, and the record cut off before the pull. The witness's memory rejects all three.
