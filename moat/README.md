# Records only a third party can hold

Two records a data vendor can bill and settle from, kept on a log no single party in the deal runs.

## Usage declaration

`shared-key/views.mjs` (`declarationOf`). The usage inventory, grouped into the vendor's own fee categories. Both sides hold the same category map (`hive.fee-categories/1`: names only, no rates), so the declaration is a pure function of the signed match, the vendor's log and that map. A holder of the shared key signs it only if its own records and its own map give the same bytes. A delivery that reached the customer with no agent record is its own line. Every line points to the vendor's fee schedule; no rate or amount is set.

Live: `shared-key/live/usage-declaration.*`, signed by the vendor and firm holders together and registered on the public log at index 93. `node tests/declaration.mjs` (12 checks, needs the stand-in holders' data).

## Derived-figure split across vendors

`moat/split.mjs`. One figure in an agent's answer built from two vendors' deliveries. The firm registers one statement that names no vendor and carries no value: the session, the answer's fingerprint, the figure, the operation, and for each input the step, the delivery fingerprint and the salted value fingerprint the recorder kept. Each vendor gets a private opening for its own input and checks it against its own delivery log, what it kept of the delivery, and its own signed copy of the session, where the other vendor's steps are fingerprints only. An auditor given every opening checks the arithmetic.

Live: `examples/claude-code-cross-vendor/`, a real Claude Code session (October 11, 2026) against two local stand-ins: Brent 84.12 USD from `market-data`, EURUSD 1.084 from `fx-data`, answer 77.60 EUR/bbl. The statement is on the public log at index 104. `node tests/split.mjs` (21 checks, 13 refusals). `node moat/build-split.mjs <tool results> <firm key> --register` rebuilds it.

Limits: both data servers are stand-ins with made-up values, and Hive made every key, including the firm's statement key. With two inputs and the result, each vendor can work out the other's number; with three or more it can't.
