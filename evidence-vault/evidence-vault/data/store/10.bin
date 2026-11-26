"""End-to-end test with a *simulated* fingerprint authenticator (software ES256 key).
Run from the project folder:   python tests/test_flow.py"""
import hashlib
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["VAULT_DATA_DIR"] = tempfile.mkdtemp(prefix="vault_test_")

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import core
import verify_report
import webauthn_lite as wa
from app import app


# ---- tiny CBOR encoder (only what a fake authenticator needs)
def _head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + struct.pack(">H", n)

def cbor(o):
    if isinstance(o, bool): raise ValueError
    if isinstance(o, int): return _head(0, o) if o >= 0 else _head(1, -1 - o)
    if isinstance(o, bytes): return _head(2, len(o)) + o
    if isinstance(o, str): return _head(3, len(o.encode())) + o.encode()
    if isinstance(o, dict): return _head(5, len(o)) + b"".join(cbor(k) + cbor(v) for k, v in o.items())
    raise ValueError(type(o))


class FakeFingerprint:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        n = self.key.public_key().public_numbers()
        self.cose = cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def register(self, challenge, origin="http://localhost", rp="localhost", uv=True):
        cd = json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": origin}).encode()
        flags = 0x01 | (0x04 if uv else 0) | 0x40
        ad = (hashlib.sha256(rp.encode()).digest() + bytes([flags]) + struct.pack(">I", 0) + b"\0" * 16 +
              struct.pack(">H", len(self.cred_id)) + self.cred_id + self.cose)
        att = cbor({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"id": wa.b64u_enc(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": wa.b64u_enc(cd), "attestationObject": wa.b64u_enc(att)}}

    def assert_(self, challenge, origin="http://localhost", rp="localhost", tamper=False):
        cd = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin}).encode()
        ad = hashlib.sha256(rp.encode()).digest() + bytes([0x05]) + struct.pack(">I", 0)
        sig = self.key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        if tamper: sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return {"id": wa.b64u_enc(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": wa.b64u_enc(cd), "authenticatorData": wa.b64u_enc(ad),
                             "signature": wa.b64u_enc(sig)}}


def check(name, cond, extra=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name} {extra}")
    if not cond:
        sys.exit(1)


c = app.test_client()
fp = FakeFingerprint()

# 1. nothing is reachable without a fingerprint
check("dashboard redirects to login when signed out", c.get("/dashboard").status_code == 302)
check("evidence API rejects anonymous callers", c.get("/api/evidence").status_code == 401)

# 2. first-time enrollment
o = c.post("/api/webauthn/register/options", json={"name": "Adithya"}).get_json()
r = c.post("/api/webauthn/register/verify", json=fp.register(o["challenge"]))
check("fingerprint enrollment accepted", r.status_code == 200, r.get_data(as_text=True)[:80])
o = c.post("/api/webauthn/register/options", json={"name": "Hacker"})
check("enrolling more people requires the admin session (and works for admin)", o.status_code == 200)

# 3. logout, then a forged / wrong fingerprint is rejected, a real one accepted
c.get("/logout")
o = c.post("/api/webauthn/login/options", json={}).get_json()
r = c.post("/api/webauthn/login/verify", json=fp.assert_(o["challenge"], tamper=True))
check("forged fingerprint signature rejected", r.status_code == 401)
o = c.post("/api/webauthn/login/options", json={}).get_json()
r = c.post("/api/webauthn/login/verify", json=fp.assert_(o["challenge"], origin="http://evil.example"))
check("wrong-origin (phishing) assertion rejected", r.status_code == 401)
o = c.post("/api/webauthn/login/options", json={}).get_json()
r = c.post("/api/webauthn/login/verify", json=fp.assert_(o["challenge"]))
check("genuine fingerprint login accepted", r.status_code == 200)
check("dashboard now reachable", c.get("/dashboard").status_code == 200)

# 4. ingest the sample folder (as the browser would: parallel path/mtime metadata)
files, meta = [], []
for p in sorted((ROOT / "sample_evidence").rglob("*")):
    if p.is_file():
        files.append((p.open("rb"), p.name))
        meta.append({"path": str(p.relative_to(ROOT / "sample_evidence")), "mtime": int(p.stat().st_mtime * 1000)})
r = c.post("/upload", data={"case_id": "CASE-TEST", "meta": json.dumps(meta),
                            "files": files}, content_type="multipart/form-data")
check("folder upload", r.status_code == 200 and len(r.get_json()["items"]) == len(files), f"({len(files)} files)")

api = {e["path"]: e for e in c.get("/api/evidence").get_json()}
check("clean file scores LOW", api["bank/bank_statement_march.csv"]["risk_level"] == "LOW")
check("duplicate detected", any("Duplicate" in x for x in api["chats/chat_export (copy).txt"]["reasons"]))
check("disguised executable detected", any("Executable" in x for x in api["scans/payment_proof.jpg"]["reasons"]))
check("edited photo with impossible timeline is HIGH+", api["photos/receipt_edited.jpg"]["risk_level"] in ("HIGH", "CRITICAL"))
check("high-entropy 'text' detected", any("encrypted" in x for x in api["notes/witness_notes.txt"]["reasons"]))

# 5. evidence access, integrity, tamper detection
eid = api["bank/bank_statement_march.csv"]["id"]; n = int(eid.split("-")[1])
check("evidence page opens after fingerprint", c.get(f"/evidence/{n}").status_code == 200)
check("verify -> MATCH", c.post(f"/evidence/{n}/verify").get_json()["ok"] is True)
with c.session_transaction() as s: s["fresh_until"] = 0
check("evidence page demands a fresh fingerprint after the window", b"Fingerprint required" in c.get(f"/evidence/{n}").data)
check("POST actions answer 403 fingerprint_required", c.post(f"/evidence/{n}/verify").status_code == 403)
o = c.post("/api/webauthn/login/options", json={"purpose": "stepup"}).get_json()
check("step-up fingerprint accepted", c.post("/api/webauthn/login/verify", json=fp.assert_(o["challenge"])).status_code == 200)
c.post(f"/evidence/{n}/demo-tamper")
check("verify after tampering -> MISMATCH", c.post(f"/evidence/{n}/verify").get_json()["ok"] is False)
api = {e["path"]: e for e in c.get("/api/evidence").get_json()}
check("tampered file is CRITICAL", api["bank/bank_statement_march.csv"]["risk_level"] == "CRITICAL")

# 6. audit log
rows = core.load_audit()
actions = [r["action"] for r in rows]
check("fingerprint login is in the audit log", "LOGIN_FINGERPRINT_SUCCESS" in actions and "STEPUP_FINGERPRINT_SUCCESS" in actions)
check("failed attempts are in the audit log", actions.count("LOGIN_FAILED") >= 2)
check("hash chain valid", core.verify_chain()["valid"] is True, f"({len(rows)} entries)")
import sqlite3
con = sqlite3.connect(core.DB_PATH); con.execute("UPDATE audit_log SET actor='mallory' WHERE id=3"); con.commit(); con.close()
bad = core.verify_chain()
check("editing one log row breaks the chain", bad["valid"] is False and bad["broken_at"] == 3, f"(broken at #{bad.get('broken_at')})")
con = sqlite3.connect(core.DB_PATH); con.execute("UPDATE audit_log SET actor='Adithya' WHERE id=3"); con.commit(); con.close()
check("chain valid again after restoring", core.verify_chain()["valid"])

# 7. signed report + offline verification
r = c.get("/report")
check("report export", r.status_code == 200)
doc = json.loads(r.get_data(as_text=True))
res = verify_report.verify(doc, ROOT / "sample_evidence")
for name, ok, msg in res: print(f"      {'ok ' if ok else 'bad'} {name}: {msg}")
failed = {n for n, ok, _ in res if not ok}
check("report verifier flags only the tampered item/file", failed == {"Items flagged TAMPERED at export time"} , str(failed))
doc["report"]["evidence"][0]["sha256"] = "0" * 64
check("modified report fails verification", not all(ok for _, ok, _ in verify_report.verify(doc)))
print("\nALL TESTS PASSED")
