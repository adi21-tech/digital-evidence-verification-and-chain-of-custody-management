#!/usr/bin/env python3
"""Offline verifier for Evidence Vault custody reports - needs no database and no server.

    python verify_report.py custody_report.json
    python verify_report.py custody_report.json --files path/to/evidence_folder

Checks: (1) report content hash, (2) Ed25519 signature, (3) the hash-chained audit log,
(4) every evidence hash matches its UPLOAD entry in the chain, (5) optionally the real files.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS = "0" * 64


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def verify(doc, files_dir=None):
    """Returns a list of (check name, passed, message)."""
    res = []
    rep = doc["report"]
    body = canon(rep).encode()

    ok = sha256_hex(body) == doc["report_sha256"]
    res.append(("Report content hash", ok, "matches" if ok else "report was modified after export"))

    try:
        ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(doc["public_key"])).verify(
            base64.b64decode(doc["signature"]), body)
        res.append(("Digital signature (Ed25519)", True,
                    f"valid - signing key {doc.get('public_key_fingerprint', '?')}"))
    except (InvalidSignature, ValueError, KeyError):
        res.append(("Digital signature (Ed25519)", False, "signature does not match the report"))

    prev, bad = GENESIS, None
    log = sorted(rep["audit_log"], key=lambda r: r["id"])
    for r in log:
        exp = sha256_hex(canon({"prev": prev, "ts": r["ts"], "actor": r["actor"], "action": r["action"],
                                "evidence": r["evidence_id"], "detail": canon(r["detail"])}).encode())
        if r["prev_hash"] != prev or exp != r["entry_hash"]:
            bad = r["id"]
            break
        prev = r["entry_hash"]
    res.append(("Audit log hash chain", bad is None,
                f"{len(log)} entries linked, head {prev[:16]}..." if bad is None else f"broken at entry #{bad}"))

    uploads = {r["evidence_id"]: r["detail"].get("sha256") for r in log if r["action"] == "UPLOAD"}
    mism = [e["id"] for e in rep["evidence"] if uploads.get(e["evidence_id"]) != e["sha256"]]
    res.append(("Evidence hashes match the audit log", not mism,
                f"{len(rep['evidence'])} items consistent" if not mism else "mismatch: " + ", ".join(mism)))

    flagged = [e["id"] for e in rep["evidence"] if e["integrity_status"] != "INTACT"]
    res.append(("Items flagged TAMPERED at export time", not flagged,
                "none" if not flagged else ", ".join(flagged)))

    if files_dir:
        root, missing, changed = Path(files_dir), [], []
        for e in rep["evidence"]:
            p = root / e["relative_path"]
            if not p.exists():
                p = root / e["filename"]
            if not p.exists():
                missing.append(e["id"])
            elif sha256_hex(p.read_bytes()) != e["sha256"]:
                changed.append(e["id"])
        res.append(("Files on disk match recorded SHA-256", not (missing or changed),
                    "all files match" if not (missing or changed)
                    else f"changed: {changed or '-'}  missing: {missing or '-'}"))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--files", help="folder with the original evidence files to re-hash")
    a = ap.parse_args()
    doc = json.loads(Path(a.report).read_text(encoding="utf-8"))
    results = verify(doc, a.files)
    for name, ok, msg in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {msg}")
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)


if __name__ == "__main__":
    main()
