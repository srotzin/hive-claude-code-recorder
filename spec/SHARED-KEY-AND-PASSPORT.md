# Shared key and answer passport

Version 2.0.0, October 11, 2026. Adds two things to the Hive Recorder formats: a signing key that no single party holds, and a passport that proves a figure an AI agent produced. Every 1.x record, statement and receipt is unchanged.

## Part 1. The shared key: hive.shared-key-ceremony/1

### What it is

One Ed25519 public key whose private half never exists in one place. Three holders, the data vendor (ICE in the demo), the customer firm and Hive, each hold a share. Any two of them can sign together. One alone cannot, and Hive alone cannot. The signature is a normal Ed25519 signature (RFC 8032), so anything that checks Ed25519 checks it, including the witness log's cosignature check and any SCITT verifier.

The scheme is FROST(Ed25519, SHA-512) from RFC 9591, with the FROST distributed key generation, using the Zcash Foundation's `frost-ed25519` 3.0.0. NCC Group audited version 0.6.0 of that library; 3.0.0 is later and has not had a separate public audit.

### Key creation

1. Each holder makes a round-one package and a fresh X25519 transport key, and signs an announcement (ceremony id, its id and name, threshold 2, the three ids, its round-one package, its transport key) with its own long-term identity key. Each holder knows the other two identity keys in advance (`peers.json`).
2. Each holder checks all three announcements against those identity keys and refuses any mismatch, including a change to its own announcement.
3. Each holder makes one secret round-two package per peer and encrypts it to that peer: X25519, then HKDF-SHA-256 with salt `hive-shared-key/dkg2` and info `<ceremony>|<from>-><to>`, then AES-256-GCM with the same string as associated data. The coordinator relays ciphertext only.
4. Each holder decrypts, finishes, rebuilds the public key package from the round-one commitments (`check_ceremony`) and seals its share at rest (scrypt N=32768, AES-256-GCM).

The ceremony record lists every announcement, signature, round-one package and the resulting public key package, plus the sha256 of the signer code each holder ran. Anyone can recheck it: each holder's proof of knowledge must verify, and the public key package must follow from the commitments. The key's first signed statement is its own ceremony record, registered on the public log.

### What each holder refuses

The signer (`shared-key/src/lib.rs`, compiled to WebAssembly) has no function that signs an arbitrary message. It signs only:

- **A log checkpoint**, as a c2sp.org/tlog-cosignature, and only when the log's own signature on the checkpoint verifies, the signing time is within 10 minutes of the holder's clock, the tree is not smaller than the last one this holder signed, a same-size tree has the same root, and an RFC 9162 consistency proof shows the new tree extends the last one it signed. The message must be exactly `cosignature/v1\ntime T\n` followed by the checkpoint body.
- **A statement**, as a COSE_Sign1 Sig_structure built inside the signer, with protected header {alg: EdDSA, content type: application/json, kid: the shared key, CWT claims {iss, sub: the statement kind}}. Only three kinds are allowed: `hive.shared-key-ceremony/1`, `hive.usage-inventory/1` and `hive.approved-calculation/1`. The payload must equal, byte for byte, the canonical JSON the holder computed itself from its own records (`shared-key/views.mjs`).

Each signing session uses fresh one-time values; a holder refuses a session it has already used and drops the values whatever the outcome. The coordinator checks every share before combining them and names the holder whose share is invalid.

### hive.usage-inventory/1

One vendor's deliveries to one customer in one period, and how they matched the customer's record. It is a pure function of the signed delivery match and the vendor's delivery log, so each holder computes the same bytes, after checking them against what it alone holds:

- vendor: its own delivery log, line for line, and its own signature on the match
- firm: its own full session records, with `checkMatch` and the witness's memory
- Hive: the witness's memory of every session in the period and of the vendor log's head

If one holder's own data disagrees, that holder refuses, and the other two can still sign only if both of their own checks pass.

## Part 2. The answer passport: hive.answer-passport/1

### What it proves

That a figure in an agent's answer is the approved calculation over exactly the values a vendor delivered and exactly the weights a firm committed to before the data arrived. It reveals the result and three commitments. It reveals no yield, benchmark, weight or bond identifier.

### Commitments: hive.poseidon-commit/1

`C = Poseidon3( Poseidon8(id[0..7]), Poseidon8(v[0..7]), salt )` over the BN254 scalar field with circomlib's Poseidon parameters. `id` is a 9-character identifier read as a base-36 number; `v` is the value in integer units (yields in thousandths of a percent); `salt` is 248 random bits.

The vendor's gateway puts the commitment in the signed delivery line (field `commitment`) and returns the salt only to the customer, in `_meta` and in the extra text block, written in letters so it adds no figures to the result. The firm registers its own commitment to its weights, signed with its key, as a SCITT statement of kind `hive.portfolio-commitment/1`.

### The calculation

`passport/circuits/spread.circom`: with spreads `d_i = y_i - b_i` in tenths of a basis point, `R = floor((2 * sum(w_i * d_i) + W) / (2W))` where `W = sum(w_i)`, which is the par-weighted average rounded half up. The same `id` signals feed all three commitments, so yields, benchmarks and weights line up bond by bond. Range checks keep yields and spreads below 2^20 and weights below 2^40 so nothing wraps.

The proof system is PLONK over BN254 (snarkjs 0.7.5). PLONK has no setup ceremony per circuit: the keys follow from the circuit and the public Perpetual Powers of Tau file `ppot_0080_14.ptau` (sha256 `3ca1149e9349b22b0ee0649399cfb787677129b7b1189d1899fc0d615d9583db`), and `passport/build.sh` rebuilds them byte for byte.

The shared key approves the calculation with a `hive.approved-calculation/1` statement that names the circuit's sha256, the verification key's sha256 (of its canonical JSON), each input's source and the output's unit and scale. Each holder re-hashes its own reviewed copy before it signs.

### Checks, in order

| Step | Refused when |
| --- | --- |
| APPROVED | the approval is not signed by the pinned shared key, its log receipt fails, or the proof's verification key is not the approved one |
| PROOF | the PLONK proof does not verify for the four public values |
| DELIVERED | the vendor's delivery log fails its chain, signatures or witness statements, the statements are not in the public log, or a delivery is the wrong tool, dataset or commitment form |
| BOUND | the proof's yield or benchmark commitment is not the one in the signed delivery line |
| WEIGHTS | the firm's commitment is not signed by the pinned firm key, its receipt fails, or it differs from the proof's |
| ORDER | the weights were logged after the first witness statement for the deliveries used |
| ANSWER | the answer's figure is not the proven result at the approved precision |

Verification needs no network. Everything except the pins (shared key, firm key, vendor key, log key, log origin) is inside the passport.

## Limits

- In the demo, Hive ran all three stand-in holders on one machine and made their identity keys. The ICE and firm holders are stand-ins. Real use needs each holder on its owner's own machine, with its own identity key.
- Attested hardware was not used. A holder's share is sealed at rest under a passphrase. Running holders inside confidential-computing enclaves needs cloud accounts the vendor and the firm hold. The signer code is reproducible instead: CI rebuilds it and compares it with the committed file, and the ceremony names its sha256.
- The firm could register several weight commitments and pick one later. Each is a signed, public log entry, so anyone watching the log sees them all; the ORDER check only proves the one used came before the data.
- The passport proves the arithmetic and the inputs. It does not prove the vendor's values are right, that the calculation is the right one to run, or that the agent understood the question.
- Zero knowledge rests on the PLONK construction and the snarkjs implementation. RISC Zero and other general-purpose proving systems were not used.
