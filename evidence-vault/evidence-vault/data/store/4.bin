# Evidence Vault — Digital Evidence Verification & Chain-of-Custody
AVISHKAR'26 · Problem 20 · Team IGRIS

Upload evidence → SHA-256 + metadata → hash-chained audit log → tamper / anomaly detection with an
explainable risk score → signed, verifiable custody report. Evidence is only reachable after a
**fingerprint scan** (Windows Hello via WebAuthn), and every scan is written to the audit log.

## Run it (Windows)
```
pip install flask cryptography pillow
python make_samples.py        # creates sample_evidence/ with deliberately suspicious files
python app.py
```
Open **http://localhost:5000** in Chrome or Edge (must be `localhost`, not `127.0.0.1`).

First visit = enroll the lead investigator's fingerprint (Windows Hello dialog). After that, every login
needs a fingerprint scan.

## 5-minute demo script
1. **Login** – scan fingerprint. Open *Audit log*: `Fingerprint login` is entry #2, hash-chained.
2. **Dashboard → Choose evidence folder** → pick `sample_evidence` → *Hash & ingest*.
3. Show the register sorted by risk. Open `photos/receipt_edited.jpg` (fingerprint prompt again) →
   *Why this risk score?* lists each reason with points (Photoshop tag, file saved before photo was taken…).
4. Other detectors: `scans/payment_proof.jpg` (executable disguised as .jpg), `chats/chat_export (copy).txt`
   (duplicate), `notes/witness_notes.txt` (encrypted-looking text), `logs/server_log_2026-03-15.txt`
   (modified before the date in its name), `memos/memo_dated_future.txt`, `memos/old_ledger.csv` (1970 timestamp).
5. **Tamper demo** – open `bank/bank_statement_march.csv` → *Simulate tampering* → *Verify integrity* →
   SHA-256 MISMATCH → CRITICAL. (Or edit a file in `data/store/` by hand – same result.)
6. **Custody transfer** – dashboard → *Enroll investigator* (second person/credential) → open an item → *Transfer custody*.
   If the second investigator opens an item they do not hold, "access outside the custody chain" is flagged.
7. **Audit log → Re-verify chain** (valid). Then change any row in `data/vault.db` and re-verify: chain breaks at that row.
8. **Export custody report (JSON)**, then verify it offline:
   `python verify_report.py custody_report_*.json --files sample_evidence`

## How requirements map to the code
| Requirement | Where |
|---|---|
| SHA-256 hashing + metadata capture | `core.ingest` (size, type, last-modified, EXIF via Pillow, entropy) |
| Hash-chained audit log of every access/transfer | `core.audit`, `core.verify_chain` (each row hashes the previous row) |
| Altered metadata, duplicates, timeline inconsistencies, unusual access | `core.static_findings`, `core.evaluate`, `core.access_anomalies` |
| Explainable risk score | every point comes from a named finding (`evaluate`) – shown on the evidence page |
| Verifiable custody report | `core.build_report` (Ed25519-signed) + standalone `verify_report.py` |
| Fingerprint-only access | `webauthn_lite.py`, `app.py` (`fresh_required` = scan within last 10 min) |
| Live dashboard / API | `/dashboard`, `/api/evidence` |

## Honest notes (say these to the judges before they ask)
- The fingerprint is checked by Windows Hello; the server only stores a public key and verifies a signature.
  WebAuthn cannot tell *which* finger – any finger enrolled in that Windows account passes, and Windows may
  offer PIN as a fallback. Each investigator = a separate passkey on the laptop (a real deployment: one device each).
- "Failed fingerprint" entries are reported by the browser (the server never sees a bad scan).
- Risk scoring is rule-based and explainable (weights in `core.py`), not a trained model. Entropy and
  timeline checks are statistical heuristics; false positives are possible (e.g. after-hours flags during an overnight hackathon).
- The chain proves *tampering with the log* is detectable; deleting only the newest entries is caught when you
  compare against a previously exported report's head hash.
- Prototype: Flask dev server on localhost, SQLite, evidence stored unencrypted in `data/store/`. Use only synthetic data.

## Files
`app.py` web app · `core.py` logic · `webauthn_lite.py` fingerprint verification · `verify_report.py` offline verifier ·
`make_samples.py` sample data · `tests/test_flow.py` end-to-end test (simulated fingerprint) · `DEMO_MODE=0` hides the tamper button.
