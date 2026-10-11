#!/usr/bin/env python3
"""Independent check, written in Python with cbor2, pycose and cryptography, sharing no code with the
JavaScript verifier. It reads the live log at witness.thehiveryiq.com and checks:

  1. the checkpoint (c2sp.org/tlog-checkpoint): the log's signature and both outside cosignatures;
  2. the Transparent Statement for the delivery match: its Signed Statement signature, and its RFC 9942
     receipt, by rebuilding the RFC 9162 root from the leaf and the inclusion path;
  3. that the receipt's tree is a prefix of the checkpoint's tree (an RFC 9162 consistency proof).

  pip install cbor2 pycose cryptography
  python3 check_independent.py
"""
import base64, hashlib, json, sys, urllib.request
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pycose.messages import Sign1Message
from pycose.keys import OKPKey
from pycose.keys.curves import Ed25519

LOG = "https://witness.thehiveryiq.com"
ORIGIN = "witness.thehiveryiq.com/log"
LOG_KEY = "FCHk4lQ-PvNo2cxkUoL0VlGuKdU6DiK-vPraAR7gyHE"
COSIGNERS = {"ice-standin.thehiveryiq.com/cosigner": "O2Y-MJxMaNvOMLGCezWaIPt0diUmIAkJn8_AfabvOqo",
             "firm-standin.thehiveryiq.com/cosigner": "H0IKgSzUtuAA-CrTRW8N81Z5w2AjxYWzOn07gYw9iw0"}
H = lambda b: hashlib.sha256(b).digest()
b64u = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
get = lambda p: urllib.request.urlopen(urllib.request.Request(LOG + p, headers={"user-agent": "hive-independent-check"})).read()
ok = True

def say(name, cond, extra=""):
    global ok
    ok = ok and cond
    print(("PASS " if cond else "FAIL ") + name + ("  " + extra if extra else ""))

def key_id(name, kind, raw):
    return H(name.encode() + b"\n" + bytes([kind]) + raw)[:4]

def verify(pub_b64u, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(b64u(pub_b64u)).verify(sig, msg)
        return True
    except Exception:
        return False

# 1. checkpoint, at the size the cosigners last signed
cos = json.loads(get("/v1/witness/log/cosignatures"))["cosignatures"]
size = max(c["tree_size"] for c in cos if c["name"] in COSIGNERS)
note = get("/v1/witness/log/checkpoint?tree_size=%d" % size).decode()
body, sigs = note.split("\n\n", 1)
body += "\n"
origin, n, root_b64 = body.split("\n")[:3]
lines = [l for l in sigs.split("\n") if l]
log_ok, cosigned = False, []
for l in lines:
    _, name, s = l.split(" ")
    raw = base64.b64decode(s)
    if name == ORIGIN and raw[:4] == key_id(ORIGIN, 1, b64u(LOG_KEY)):
        log_ok = log_ok or verify(LOG_KEY, body.encode(), raw[4:])
    if name in COSIGNERS and len(raw) == 76 and raw[:4] == key_id(name, 4, b64u(COSIGNERS[name])):
        t = int.from_bytes(raw[4:12], "big")
        if verify(COSIGNERS[name], ("cosignature/v1\ntime %d\n" % t).encode() + body.encode(), raw[12:]):
            cosigned.append(name)
say("checkpoint signed by the log key", origin == ORIGIN and log_ok, "size %s" % n)
say("checkpoint cosigned by both outside cosigners", sorted(cosigned) == sorted(COSIGNERS), ", ".join(sorted(cosigned)))
cp_root, cp_size = base64.b64decode(root_b64), int(n)

# 2. the Transparent Statement
here = __file__.rsplit("/", 1)[0] if "/" in __file__ else "."
ts = cbor2.loads(open(here + "/scitt/match.transparent.cose", "rb").read())
prot, unprot, payload, sig = ts.value
ph = cbor2.loads(prot)
issuer = ph[4].decode()
ss = Sign1Message.from_cose_obj([prot, {}, payload, sig], True)
ss.key = OKPKey(crv=Ed25519, x=b64u(issuer))
say("Signed Statement verifies with its issuer key (pycose)", ss.verify_signature(), "iss=%s" % ph[15][1])
entry = cbor2.dumps(cbor2.CBORTag(18, [prot, {}, payload, sig]))
receipt = unprot[394][0]
rt = cbor2.loads(receipt)
rprot, runprot, _, rsig = rt.value
rph = cbor2.loads(rprot)
say("receipt is RFC 9942 with vds RFC9162_SHA256", rph[395] == 1 and rph[1] == -8)
tsize, idx, path = cbor2.loads(runprot[396][-1][0])
fn, sn, r = idx, tsize - 1, H(b"\0" + entry)
for p in path:
    if fn & 1 or fn == sn:
        r = H(b"\1" + p + r)
        if not fn & 1:
            while not fn & 1 and fn:
                fn >>= 1; sn >>= 1
    else:
        r = H(b"\1" + r + p)
    fn >>= 1; sn >>= 1
rm = Sign1Message.from_cose_obj([rprot, dict(runprot), None, rsig], True)
rm.payload = r
rm.key = OKPKey(crv=Ed25519, x=b64u(LOG_KEY))
say("receipt verifies over the root rebuilt from the entry (pycose)", sn == 0 and rm.verify_signature(), "leaf %d of %d" % (idx, tsize))

# 3. the receipt's tree is a prefix of the cosigned checkpoint's tree
if tsize == cp_size:
    say("receipt tree and checkpoint tree are the same", r == cp_root)
elif tsize < cp_size:
    proof = [bytes.fromhex(h) for h in json.loads(get("/v1/witness/log/consistency?first=%d&second=%d" % (tsize, cp_size)))["path"]]
    p = ([r] if tsize & (tsize - 1) == 0 else []) + proof
    fn, sn = tsize - 1, cp_size - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if fn & 1 or fn == sn:
            fr = H(b"\1" + c + fr); sr = H(b"\1" + c + sr)
            if not fn & 1:
                while not fn & 1 and fn:
                    fn >>= 1; sn >>= 1
        else:
            sr = H(b"\1" + sr + c)
        fn >>= 1; sn >>= 1
    say("receipt tree (%d) is a prefix of the cosigned tree (%d)" % (tsize, cp_size), fr == r and sr == cp_root and sn == 0)
else:
    print("NOTE the cosigners have not yet signed a tree that includes this receipt (%d > %d)" % (tsize, cp_size))
sys.exit(0 if ok else 1)
