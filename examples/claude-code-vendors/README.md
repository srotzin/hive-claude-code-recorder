# Two data vendors, one witness

Recorded on October 10, 2026 with Claude Code and Hive Recorder 1.3.0, in service mode: recorderd ran as its own system user and held the keys and the records.

- The admission, read from `/etc/hive/admission-vendors.json`, gave two vendors their own entitlements: `market-data` for `futures.brent.*` and `futures.wti.eod`, `ref-data` for `issuers.reference`.
- Both MCP servers are local stand-ins (`market-data-standin.mjs`, `ref-data-standin.mjs`). Their values are made up and every reply says so.
- Session 1: Claude pulled Brent settlements (inside), 5 rows of `mortgage.loan-level` (outside market-data's entitlement, flagged at line 10) and an issuer record from ref-data (inside). Its answer, `answer-1.txt`, repeats figures from all three, and line 14 records which.
- Session 2: Claude pulled WTI settlements (inside).
- Hive's live witness signed before each call ran and remembers every statement. DigiCert stamped the start and the seals.

`copies/` holds what each vendor gets: its own lines in full, everything else as digest only, plus market-data's licence statement for the period, signed with the recorder key and accepted with a stand-in vendor key Hive generated for this demo.

```
V=../../plugins/hive-recorder/scripts/verify.mjs
node $V copies/session-1.market-data.jsonl --key key.json --disclose-for market-data --ask-witness --witness /none
node $V copies/session-1.ref-data.jsonl --key key.json --disclose-for ref-data --ask-witness --witness /none
node $V answer copies/session-1.market-data.jsonl --text answer-1.txt
node $V statement copies/statement.market-data.json copies/session-1.market-data.jsonl copies/session-2.market-data.jsonl --ask-witness --key key.json --vendor-key copies/vendor-key.market-data.json
```

`tamper/` holds 14 changed copies, built by `tests/vendor-tamper.mjs`: four hiding tricks in a vendor's copy, three across the two vendors, three on the answer trail and four on the statement. Every one is rejected, eight of them only because the witness remembers.
