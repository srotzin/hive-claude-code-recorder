//! Hive shared key.
//!
//! One Ed25519 signing key that three parties (ICE, the firm, Hive) create together and that no
//! party ever holds whole. Any two of the three can sign; one alone cannot. Signatures are plain
//! RFC 8032 Ed25519, so every existing verifier accepts them unchanged.
//!
//! Key creation and signing are the Zcash Foundation `frost-ed25519` crate (FROST, RFC 9591, with the
//! FROST DKG for key creation). This file adds the rules each party enforces before it lends its share:
//!
//!   * checkpoints: it signs a witness log checkpoint (c2sp.org/tlog-checkpoint, as a
//!     c2sp.org/tlog-cosignature) only if the log's own signature on it verifies and the tree extends
//!     the last tree this party signed (RFC 9162 consistency proof). It never signs two different trees
//!     of the same size, and never a smaller tree.
//!   * statements: it signs a SCITT Signed Statement (RFC 9943, COSE_Sign1) whose payload is one of a few
//!     statement kinds (the key's own ceremony record, a usage inventory, an approved calculation), and only
//!     if the payload is byte for byte what this party computed from its own records.
//!
//! There is no function that signs an arbitrary message.
//!
//! The same file is compiled to WebAssembly and called from Node or a browser through one entry point,
//! `hive_call`, which takes and returns JSON.

use base64::Engine;
use frost_ed25519 as frost;
use frost::keys::{dkg, KeyPackage, PublicKeyPackage};
use frost::{round1, round2, Identifier, Signature, SigningPackage, VerifyingKey};
use rand_core::OsRng;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const STATEMENT_KINDS: [&str; 3] = ["hive.shared-key-ceremony/1", "hive.usage-inventory/1", "hive.approved-calculation/1"];
pub const MAX_CLOCK_SKEW: i64 = 600;

type Res = Result<Value, String>;

fn err<E: core::fmt::Debug>(x: E) -> String { format!("{:?}", x) }
fn b64u() -> base64::engine::GeneralPurpose { base64::engine::general_purpose::URL_SAFE_NO_PAD }
fn b64() -> base64::engine::GeneralPurpose { base64::engine::general_purpose::STANDARD }

fn get<'a>(a: &'a Value, k: &str) -> Result<&'a Value, String> { a.get(k).ok_or_else(|| format!("missing {}", k)) }
fn s<'a>(a: &'a Value, k: &str) -> Result<&'a str, String> { get(a, k)?.as_str().ok_or_else(|| format!("{} must be a string", k)) }
fn u(a: &Value, k: &str) -> Result<u64, String> { get(a, k)?.as_u64().ok_or_else(|| format!("{} must be a whole number", k)) }
fn i(a: &Value, k: &str) -> Result<i64, String> { get(a, k)?.as_i64().ok_or_else(|| format!("{} must be a whole number", k)) }
fn hx(a: &Value, k: &str) -> Result<Vec<u8>, String> { hex::decode(s(a, k)?).map_err(|_| format!("{} must be hex", k)) }

fn ident(n: u64) -> Result<Identifier, String> {
    if n == 0 || n > 255 { return Err("participant number must be 1 to 255".into()); }
    Identifier::try_from(n as u16).map_err(err)
}
fn ident_num(id: &Identifier) -> Result<u64, String> {
    for n in 1..=255u64 { if ident(n)? == *id { return Ok(n); } }
    Err("participant number out of range".into())
}
// {"1": "<hex>", "2": "<hex>"} -> BTreeMap<Identifier, T>
fn id_map<T>(v: &Value, de: impl Fn(&[u8]) -> Result<T, String>) -> Result<BTreeMap<Identifier, T>, String> {
    let o = v.as_object().ok_or("expected an object keyed by participant number")?;
    let mut m = BTreeMap::new();
    for (k, x) in o {
        let n: u64 = k.parse().map_err(|_| format!("bad participant number {}", k))?;
        let bytes = hex::decode(x.as_str().ok_or("expected hex")?).map_err(|_| "expected hex".to_string())?;
        m.insert(ident(n)?, de(&bytes)?);
    }
    Ok(m)
}

// ---------------------------------------------------------------- key creation (FROST DKG)

fn dkg1(a: &Value) -> Res {
    let (secret, pkg) = dkg::part1(ident(u(a, "id")?)?, u(a, "max")? as u16, u(a, "min")? as u16, OsRng).map_err(err)?;
    Ok(json!({ "secret": serde_json::to_value(&secret).map_err(err)?, "package": hex::encode(pkg.serialize().map_err(err)?) }))
}
fn dkg2(a: &Value) -> Res {
    let secret: dkg::round1::SecretPackage = serde_json::from_value(get(a, "secret")?.clone()).map_err(err)?;
    let r1 = id_map(get(a, "round1")?, |b| dkg::round1::Package::deserialize(b).map_err(err))?;
    let (secret2, out) = dkg::part2(secret, &r1).map_err(err)?;
    let mut pk = Map::new();
    for (id, p) in out { pk.insert(ident_num(&id)?.to_string(), Value::String(hex::encode(p.serialize().map_err(err)?))); }
    Ok(json!({ "secret": serde_json::to_value(&secret2).map_err(err)?, "packages": pk }))
}
fn dkg3(a: &Value) -> Res {
    let secret: dkg::round2::SecretPackage = serde_json::from_value(get(a, "secret")?.clone()).map_err(err)?;
    let r1 = id_map(get(a, "round1")?, |b| dkg::round1::Package::deserialize(b).map_err(err))?;
    let r2 = id_map(get(a, "round2")?, |b| dkg::round2::Package::deserialize(b).map_err(err))?;
    let (kp, pkp) = dkg::part3(&secret, &r1, &r2).map_err(err)?;
    Ok(json!({
        "key_package": hex::encode(kp.serialize().map_err(err)?),
        "public_key_package": hex::encode(pkp.serialize().map_err(err)?),
        "group_key": b64u().encode(pkp.verifying_key().serialize().map_err(err)?),
    }))
}

// Anyone can run this on the published ceremony record: every party proved it knows the secret behind
// its commitment, and the published group key and per-party public shares follow from the commitments.
fn check_ceremony(a: &Value) -> Res {
    let r1 = id_map(get(a, "round1")?, |b| dkg::round1::Package::deserialize(b).map_err(err))?;
    let pkp = PublicKeyPackage::deserialize(&hx(a, "public_key_package")?).map_err(err)?;
    let mut proofs = Vec::new();
    for (id, p) in &r1 {
        frost_core::keys::dkg::verify_proof_of_knowledge(*id, p.commitment(), p.proof_of_knowledge())
            .map_err(|e| format!("participant {} did not prove its commitment: {:?}", ident_num(id).unwrap_or(0), e))?;
        proofs.push(ident_num(id)?);
    }
    let commits: BTreeMap<Identifier, &frost_core::keys::VerifiableSecretSharingCommitment<frost::Ed25519Sha512>> =
        r1.iter().map(|(id, p)| (*id, p.commitment())).collect();
    let rebuilt = PublicKeyPackage::from_dkg_commitments(&commits).map_err(err)?;
    if rebuilt.verifying_key() != pkp.verifying_key() { return Err("the group key does not follow from the published commitments".into()); }
    if rebuilt.verifying_shares() != pkp.verifying_shares() { return Err("a party's public share does not follow from the published commitments".into()); }
    let min = pkp.min_signers().ok_or("public key package does not state how many signers are needed")?;
    let mut shares = Map::new();
    for (id, v) in pkp.verifying_shares() { shares.insert(ident_num(id)?.to_string(), Value::String(hex::encode(v.serialize().map_err(err)?))); }
    Ok(json!({ "ok": true, "proofs_checked": proofs, "parties": pkp.verifying_shares().len(), "min_signers": min,
               "group_key": b64u().encode(pkp.verifying_key().serialize().map_err(err)?), "verifying_shares": shares }))
}

// ---------------------------------------------------------------- signing

fn commit(a: &Value) -> Res {
    let kp = KeyPackage::deserialize(&hx(a, "key_package")?).map_err(err)?;
    let (nonces, c) = round1::commit(kp.signing_share(), &mut OsRng);
    Ok(json!({ "nonces": serde_json::to_value(&nonces).map_err(err)?, "commitments": hex::encode(c.serialize().map_err(err)?) }))
}
fn signing_package(a: &Value) -> Res {
    let c = id_map(get(a, "commitments")?, |b| round1::SigningCommitments::deserialize(b).map_err(err))?;
    let sp = SigningPackage::new(c, &hx(a, "message")?);
    Ok(json!({ "signing_package": hex::encode(sp.serialize().map_err(err)?) }))
}
fn share(a: &Value, sp: &SigningPackage) -> Result<String, String> {
    let kp = KeyPackage::deserialize(&hx(a, "key_package")?).map_err(err)?;
    let nonces: round1::SigningNonces = serde_json::from_value(get(a, "nonces")?.clone()).map_err(err)?;
    let sh = round2::sign(sp, &nonces, &kp).map_err(|e| match e {
        frost::Error::IncorrectNumberOfCommitments => "not enough parties: this key needs at least 2 of its 3 holders to sign".to_string(),
        other => err(other),
    })?;
    Ok(hex::encode(sh.serialize()))
}

// RFC 9162 section 2.1.4.2
fn node(l: &[u8], r: &[u8]) -> [u8; 32] { let mut h = Sha256::new(); h.update([1u8]); h.update(l); h.update(r); h.finalize().into() }
pub fn verify_consistency(size1: u64, size2: u64, root1: &[u8], root2: &[u8], path: &[Vec<u8>]) -> bool {
    if size1 > size2 { return false; }
    if size1 == size2 { return path.is_empty() && root1 == root2; }
    if size1 == 0 { return path.is_empty(); }
    if path.is_empty() { return false; }
    let mut p: Vec<Vec<u8>> = Vec::new();
    if size1 & (size1 - 1) == 0 { p.push(root1.to_vec()); }
    p.extend(path.iter().cloned());
    let (mut fnn, mut sn) = (size1 - 1, size2 - 1);
    while fnn & 1 == 1 { fnn >>= 1; sn >>= 1; }
    let (mut fr, mut sr) = (p[0].clone(), p[0].clone());
    for c in &p[1..] {
        if sn == 0 { return false; }
        if fnn & 1 == 1 || fnn == sn {
            fr = node(c, &fr).to_vec(); sr = node(c, &sr).to_vec();
            if fnn & 1 == 0 { while fnn & 1 == 0 && fnn != 0 { fnn >>= 1; sn >>= 1; } }
        } else { sr = node(&sr, c).to_vec(); }
        fnn >>= 1; sn >>= 1;
    }
    fr == root1 && sr == root2 && sn == 0
}

struct Checkpoint { body: String, origin: String, size: u64, root: Vec<u8>, sigs: Vec<(String, Vec<u8>)> }
fn parse_checkpoint(t: &str) -> Result<Checkpoint, String> {
    let i = t.find("\n\n").ok_or("not a signed note")?;
    let body = t[..i + 1].to_string();
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() < 4 { return Err("checkpoint body is too short".into()); }
    let size: u64 = lines[1].parse().map_err(|_| "bad tree size".to_string())?;
    let root = b64().decode(lines[2]).map_err(|_| "bad root hash".to_string())?;
    if root.len() != 32 { return Err("root hash must be 32 bytes".into()); }
    let mut sigs = Vec::new();
    for l in t[i + 2..].split('\n').filter(|l| !l.is_empty()) {
        let rest = l.strip_prefix("\u{2014} ").ok_or("bad signature line")?;
        let (name, sig) = rest.rsplit_once(' ').ok_or("bad signature line")?;
        sigs.push((name.to_string(), b64().decode(sig).map_err(|_| "bad signature encoding".to_string())?));
    }
    let origin = lines[0].to_string();
    Ok(Checkpoint { body: body.clone(), origin, size, root, sigs })
}
fn key_id(name: &str, kind: u8, raw: &[u8]) -> [u8; 4] {
    let mut h = Sha256::new(); h.update(name.as_bytes()); h.update([0x0a, kind]); h.update(raw);
    let d: [u8; 32] = h.finalize().into(); [d[0], d[1], d[2], d[3]]
}
fn check_log_signature(cp: &Checkpoint, origin: &str, log_key: &[u8]) -> Result<(), String> {
    if cp.origin != origin { return Err("the checkpoint names a different log".into()); }
    let raw: [u8; 32] = log_key.try_into().map_err(|_| "log key must be 32 bytes".to_string())?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(err)?;
    let id = key_id(origin, 1, &raw);
    for (name, sig) in &cp.sigs {
        if name != origin || sig.len() != 68 || sig[..4] != id { continue; }
        let sg = ed25519_dalek::Signature::from_slice(&sig[4..]).map_err(err)?;
        if vk.verify_strict(cp.body.as_bytes(), &sg).is_ok() { return Ok(()); }
    }
    Err("the log's own signature on the checkpoint does not verify".into())
}

// The checkpoint rule. Returns the message to sign and this party's new state.
fn checkpoint_rule(a: &Value) -> Result<(String, Value), String> {
    let cp = parse_checkpoint(s(a, "checkpoint")?)?;
    check_log_signature(&cp, s(a, "origin")?, &b64u().decode(s(a, "log_key")?).map_err(|_| "log key must be base64url".to_string())?)?;
    let (t, now) = (i(a, "time")?, i(a, "now")?);
    if (t - now).abs() > MAX_CLOCK_SKEW { return Err("the proposed signing time is more than 10 minutes from this party's clock".into()); }
    let st = get(a, "state")?;
    if !st.is_null() {
        let (size, root) = (u(st, "size")?, hex::decode(s(st, "root")?).map_err(|_| "state root must be hex".to_string())?);
        if cp.size < size { return Err(format!("refused: the log went back from {} to {}", size, cp.size)); }
        if cp.size == size && cp.root != root { return Err(format!("refused: two different trees of size {}", size)); }
        if cp.size > size {
            let path: Vec<Vec<u8>> = get(a, "proof")?.as_array().ok_or("proof must be a list")?.iter()
                .map(|x| hex::decode(x.as_str().unwrap_or("")).map_err(|_| "proof hash must be hex".to_string())).collect::<Result<_, _>>()?;
            if !verify_consistency(size, cp.size, &root, &cp.root, &path) {
                return Err(format!("refused: the tree at {} does not extend the tree at {} this party already signed", cp.size, size));
            }
        }
    }
    Ok((format!("cosignature/v1\ntime {}\n{}", t, cp.body), json!({ "size": cp.size, "root": hex::encode(&cp.root) })))
}
fn checkpoint_message(a: &Value) -> Res {
    let (m, st) = checkpoint_rule(a)?;
    Ok(json!({ "message": hex::encode(m.as_bytes()), "state": st }))
}
fn sign_checkpoint(a: &Value) -> Res {
    let (m, st) = checkpoint_rule(a)?;
    let sp = SigningPackage::deserialize(&hx(a, "signing_package")?).map_err(err)?;
    if sp.message() != m.as_bytes() { return Err("refused: the coordinator asked to sign something other than this checkpoint".into()); }
    Ok(json!({ "share": share(a, &sp)?, "state": st }))
}

// The statement rule. The shared key signs only COSE Sig_structures (RFC 9052) built here, over a
// canonical JSON payload (serde_json without preserve_order sorts object keys) of an allowed kind.
fn cbor_head(major: u8, n: usize, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 { out.push(m | n as u8); }
    else if n < 256 { out.push(m | 24); out.push(n as u8); }
    else if n < 65536 { out.push(m | 25); out.extend_from_slice(&(n as u16).to_be_bytes()); }
    else { out.push(m | 26); out.extend_from_slice(&(n as u32).to_be_bytes()); }
}
fn cbor_text(x: &str, out: &mut Vec<u8>) { cbor_head(3, x.len(), out); out.extend_from_slice(x.as_bytes()); }
fn cbor_bytes(x: &[u8], out: &mut Vec<u8>) { cbor_head(2, x.len(), out); out.extend_from_slice(x); }
fn ascii_label(x: &str, what: &str) -> Result<(), String> {
    if x.is_empty() || x.len() > 200 || !x.bytes().all(|c| (0x21..=0x7e).contains(&c)) { return Err(format!("{} must be 1 to 200 printable ASCII characters", what)); }
    Ok(())
}
struct Stmt { protected: Vec<u8>, payload: Vec<u8>, to_sign: Vec<u8> }
fn statement_bytes(a: &Value, stmt: &Value) -> Result<Stmt, String> {
    let kind = s(stmt, "kind")?;
    if !STATEMENT_KINDS.contains(&kind) { return Err(format!("refused: this key does not sign statements of kind {}", kind)); }
    let payload = serde_json::to_string(stmt).map_err(err)?;
    if !payload.is_ascii() { return Err("statements must be ASCII".into()); }
    let (kid, iss) = (s(a, "group_key")?, s(a, "iss")?);
    ascii_label(kid, "group key")?; ascii_label(iss, "issuer")?;
    // protected header {1: -8 (EdDSA), 3: "application/json", 4: kid, 15: {1: iss, 2: kind}}
    let mut prot = vec![0xa4, 0x01, 0x27, 0x03];
    cbor_text("application/json", &mut prot);
    prot.push(0x04); cbor_bytes(kid.as_bytes(), &mut prot);
    prot.extend_from_slice(&[0x0f, 0xa2, 0x01]); cbor_text(iss, &mut prot);
    prot.push(0x02); cbor_text(kind, &mut prot);
    let mut ts = vec![0x84];
    cbor_text("Signature1", &mut ts); cbor_bytes(&prot, &mut ts); cbor_bytes(&[], &mut ts); cbor_bytes(payload.as_bytes(), &mut ts);
    Ok(Stmt { protected: prot, payload: payload.into_bytes(), to_sign: ts })
}
fn statement_message(a: &Value) -> Res {
    let st = statement_bytes(a, get(a, "statement")?)?;
    Ok(json!({ "message": hex::encode(&st.to_sign), "protected": hex::encode(&st.protected), "payload": hex::encode(&st.payload) }))
}
fn sign_statement(a: &Value) -> Res {
    let st = statement_bytes(a, get(a, "statement")?)?;
    if statement_bytes(a, get(a, "my_view")?)?.to_sign != st.to_sign { return Err("refused: the statement differs from what this party computed from its own records".into()); }
    let sp = SigningPackage::deserialize(&hx(a, "signing_package")?).map_err(err)?;
    if sp.message() != st.to_sign.as_slice() { return Err("refused: the coordinator asked to sign something other than this statement".into()); }
    Ok(json!({ "share": share(a, &sp)? }))
}

// ---------------------------------------------------------------- checking

fn verify_share(a: &Value) -> Res {
    let pkp = PublicKeyPackage::deserialize(&hx(a, "public_key_package")?).map_err(err)?;
    let sp = SigningPackage::deserialize(&hx(a, "signing_package")?).map_err(err)?;
    let id = ident(u(a, "id")?)?;
    let vs = pkp.verifying_shares().get(&id).ok_or("unknown participant")?;
    let sh = round2::SignatureShare::deserialize(&hx(a, "share")?).map_err(err)?;
    frost_core::verify_signature_share(id, vs, &sh, &sp, pkp.verifying_key()).map_err(|_| format!("participant {}'s share does not verify", u(a, "id").unwrap_or(0)))?;
    Ok(json!({ "ok": true }))
}
fn aggregate(a: &Value) -> Res {
    let pkp = PublicKeyPackage::deserialize(&hx(a, "public_key_package")?).map_err(err)?;
    let sp = SigningPackage::deserialize(&hx(a, "signing_package")?).map_err(err)?;
    let shares = id_map(get(a, "shares")?, |b| round2::SignatureShare::deserialize(b).map_err(err))?;
    let min = pkp.min_signers().unwrap_or(2) as usize;
    if shares.len() < min { return Err(format!("not enough parties: {} share(s), this key needs {}", shares.len(), min)); }
    let sig = frost::aggregate(&sp, &shares, &pkp).map_err(|e| match e {
        frost::Error::InvalidSignatureShare { culprits } => format!("rejected: the share from participant {} is not valid",
            culprits.iter().map(|c| ident_num(c).map(|n| n.to_string()).unwrap_or_default()).collect::<Vec<_>>().join(", ")),
        other => err(other),
    })?;
    Ok(json!({ "signature": hex::encode(sig.serialize().map_err(err)?) }))
}
fn verify(a: &Value) -> Res {
    let vk = VerifyingKey::deserialize(&b64u().decode(s(a, "group_key")?).map_err(|_| "group key must be base64url".to_string())?).map_err(err)?;
    let sig = Signature::deserialize(&hx(a, "signature")?).map_err(err)?;
    vk.verify(&hx(a, "message")?, &sig).map_err(|_| "the signature does not verify under the shared key".to_string())?;
    Ok(json!({ "ok": true }))
}
fn version(_: &Value) -> Res {
    Ok(json!({ "crate": "hive-shared-key 2.0.0", "frost": "frost-ed25519 =3.0.0 (Zcash Foundation)", "suite": "FROST(Ed25519, SHA-512), RFC 9591",
               "statement_kinds": STATEMENT_KINDS, "max_clock_skew_seconds": MAX_CLOCK_SKEW }))
}

pub fn dispatch(input: &str) -> Value {
    let req: Value = match serde_json::from_str(input) { Ok(v) => v, Err(e) => return json!({ "error": format!("bad request: {}", e) }) };
    let a = req.get("args").cloned().unwrap_or(Value::Null);
    let r = match req.get("fn").and_then(|x| x.as_str()).unwrap_or("") {
        "version" => version(&a), "dkg1" => dkg1(&a), "dkg2" => dkg2(&a), "dkg3" => dkg3(&a), "check_ceremony" => check_ceremony(&a),
        "commit" => commit(&a), "signing_package" => signing_package(&a),
        "checkpoint_message" => checkpoint_message(&a), "sign_checkpoint" => sign_checkpoint(&a),
        "statement_message" => statement_message(&a), "sign_statement" => sign_statement(&a),
        "verify_share" => verify_share(&a), "aggregate" => aggregate(&a), "verify" => verify(&a),
        other => Err(format!("unknown function {}", other)),
    };
    match r { Ok(v) => json!({ "ok": v }), Err(e) => json!({ "error": e }) }
}

// ---------------------------------------------------------------- WebAssembly entry points

#[cfg(target_arch = "wasm32")]
mod wasm {
    extern "C" { fn hive_random(ptr: *mut u8, len: usize); }
    fn fill(buf: &mut [u8]) -> Result<(), getrandom::Error> { unsafe { hive_random(buf.as_mut_ptr(), buf.len()) }; Ok(()) }
    getrandom::register_custom_getrandom!(fill);

    #[no_mangle]
    pub extern "C" fn hive_alloc(n: usize) -> *mut u8 { let mut v = Vec::<u8>::with_capacity(n.max(1)); let p = v.as_mut_ptr(); core::mem::forget(v); p }
    #[no_mangle]
    pub unsafe extern "C" fn hive_free(p: *mut u8, n: usize) { drop(Vec::from_raw_parts(p, 0, n.max(1))); }
    // Returns (ptr << 32) | len of a UTF-8 JSON reply; the caller frees it with hive_free(ptr, len).
    #[no_mangle]
    pub unsafe extern "C" fn hive_call(p: *const u8, n: usize) -> u64 {
        let input = core::str::from_utf8(core::slice::from_raw_parts(p, n)).unwrap_or("");
        let out = super::dispatch(input).to_string().into_bytes().into_boxed_slice();
        let len = out.len();
        let ptr = Box::into_raw(out) as *mut u8;
        ((ptr as u64) << 32) | (len as u64)
    }
}
