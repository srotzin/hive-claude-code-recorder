# Two real Claude Code sessions through the gateway, matched both ways, with standard receipts

Recorded October 11, 2026 (UTC) with Claude Code 2.1.296 and plugin 1.4.0 in service mode. Claude Code reached the vendor over HTTP MCP through `vendor-kit/mcp-gateway.mjs`. Behind the gateway is `plain-mcp-http.mjs`, a vendor MCP server with no Hive code, answering in SSE. Every value it returns is made up, and every reply says so.

- `session-1.jsonl`: Claude pulls Brent and WTI, then answers with the spread, the ratio and Brent's percentage change (`answer-1.txt`).
- `session-2.jsonl`: Claude pulls 5 mortgage rows, outside the market-data entitlement in `hive-admission.json`, then answers with the total and the largest loan's share (`answer-2.txt`).
- After the two sessions, one Brent pull went straight to the gateway with the firm's token, outside Claude Code and its recorder.
- `vendor/`: the gateway's signed log for this customer, 4 deliveries, each witnessed before the data went out, and the bodies the vendor kept. In use, only the vendor holds the bodies.
- `copies/`: market-data's copy of each session and `match.market-data.json`, signed by the stand-in vendor key and accepted by the firm's recorder key: 3 pulls matched, 1 delivered with no record, 0 recorded with no delivery. The period is in `period.txt`.
- `scitt/`: the match registered on the witness's public log as a SCITT Signed Statement, its RFC 9942 receipt, and the Transparent Statement. `scitt/superseded/` holds a first registration (log entry 75) of a match whose period also covered four test sessions run against other gateway logs a few minutes earlier. The completeness check refused it for leaving those sessions out, which is the check doing its job; the match here starts after them.
- `cosigners.json`: the two stand-in cosigners that cosign the log's checkpoint.

From the vendor's kept bodies, every computed figure traces to exactly one operation:

| Answer | Operation | From |
| --- | --- | --- |
| 4.77 | difference | Brent settle (delivery 0) minus WTI settle (delivery 1) |
| 1.06 | ratio | Brent settle over WTI settle, across deliveries 0 and 1 |
| 2.71% | percent change | Brent settle over its prior settle, delivery 0 |
| $1,260,000 | sum | the 5 balances in delivery 2 |
| 20.16% | share | loan L1004's balance over that total |

A finding from the run: with the delivery id only in `result._meta`, the recorder did not see it, because Claude Code 2.1.296 does not pass `_meta` to hooks. With the id also as one text block, it saw every pull. The gateway does both by default.

`node tests/gateway-live.mjs <vendor-key.pem>` checks all of it against the live witness, its public log and the cosigned checkpoint, then rejects 9 rewrites (`RESULTS-live.txt`). `python3 check_independent.py` checks the checkpoint, both cosignatures and the receipt in Python with cbor2, pycose and cryptography (`RESULTS-independent.txt`).

Limits: Hive ran the witness, the gateway, both cosigners and the vendor server, and generated every key. The cosigners show the mechanism; they are independent only when ICE and the firm hold their own cosigner keys.
