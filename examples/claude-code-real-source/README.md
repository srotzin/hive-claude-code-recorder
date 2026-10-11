# Real ICE index data, two publishers, one figure

Recorded October 11, 2026 with Claude Code in service mode. Two thin MCP adapters ran on the firm's side:

- `ice-indices`: ICE Data Indices' published index data as distributed by FRED (St. Louis Fed) under ICE's licence. Series BAMLH0A0HYM2EY, the ICE BofA US High Yield Index effective yield, for 2026-10-08.
- `us-treasury`: the U.S. Treasury's daily par yield curve, 10-year, same date: 5.22.

Claude Code answered with the high-yield spread over the 10-year Treasury: 289 bp. Each adapter fetched its source live, signed a delivery line and had the witness countersign it before the data went to the agent. The delivery line's fingerprint covers the SHA-256 of the exact bytes the source returned.

This folder never reproduces the ICE value. `answer.masked.txt` masks it, there is no opening for ICE's input, and no kept body for it. ICE's side of the check rebuilds both from the public source: `node tests/split-real.mjs` re-fetches FRED, rebuilds the delivered body, matches it to the signed delivery line, and opens ICE's input in the registered split (public log index 113) with the value it fetched.

Limits: the adapters, their keys and the firm's statement key were run and made by Hive. ICE's own systems are not connected; the data is ICE's, through its public distribution.
