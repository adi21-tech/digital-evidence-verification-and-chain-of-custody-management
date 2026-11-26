"""Creates a synthetic 'sample_evidence' folder (non-sensitive) with deliberately suspicious files
so every detector in Evidence Vault can be demonstrated.   python make_samples.py"""
import datetime as dt
import os
import random
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent / "sample_evidence"
random.seed(7)


def stamp(path, when):
    t = when.timestamp()
    os.utime(path, (t, t))


def write(rel, data, when):
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    stamp(p, when)
    return p


def photo(rel, when, software=None, exif_original="2026-02-10 14:05:00", exif_modified=None):
    p = OUT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (640, 360), (240, 240, 235))
    d = ImageDraw.Draw(img)
    d.text((30, 30), "SYNTHETIC SAMPLE RECEIPT", fill=(20, 20, 20))
    d.text((30, 80), "Amount: 48,500.00", fill=(20, 20, 20))
    for i in range(12):
        d.rectangle([30, 130 + i * 15, 30 + random.randint(120, 500), 138 + i * 15], fill=(200, 200, 195))
    ex = Image.Exif()
    ex[271], ex[272] = "Canon", "EOS 1500D"
    if software:
        ex[305] = software
    ex[306] = (exif_modified or exif_original).replace("-", ":", 2)
    sub = ex.get_ifd(0x8769)
    sub[36867] = exif_original.replace("-", ":", 2)
    img.save(p, "JPEG", exif=ex)
    stamp(p, when)


D = dt.datetime
OUT.mkdir(exist_ok=True)

# --- clean, consistent files
write("bank/bank_statement_march.csv",
      "date,narration,amount\n2026-03-01,SALARY,52000\n2026-03-04,UPI-RAHUL,-12000\n2026-03-09,ATM,-5000\n",
      D(2026, 3, 31, 18, 0))
write("chats/chat_export.txt", "[10:02] A: transfer done?\n[10:03] B: yes, check account\n", D(2026, 3, 12, 11, 30))
photo("photos/receipt_original.jpg", D(2026, 2, 10, 14, 6))

# --- suspicious files (each triggers one detector)
write("chats/chat_export (copy).txt", "[10:02] A: transfer done?\n[10:03] B: yes, check account\n",
      D(2026, 3, 12, 11, 31))                                                        # duplicate content
photo("photos/receipt_edited.jpg", D(2026, 2, 12, 9, 0), software="Adobe Photoshop 25.0",
      exif_original="2026-06-01 10:00:00", exif_modified="2026-06-03 21:15:00")      # editor + impossible timeline
write("logs/server_log_2026-03-15.txt", "Mar 15 02:11 login ok user=admin\nMar 15 02:13 export db\n",
      D(2026, 1, 2, 8, 0))                                                           # modified before date in its name
write("scans/payment_proof.jpg", b"MZ\x90\x00\x03\x00\x00\x00" + b"HARMLESS SYNTHETIC TEST BYTES " * 20,
      D(2026, 3, 20, 10, 0))                                                         # 'executable' disguised as jpg
write("notes/witness_notes.txt", os.urandom(6000), D(2026, 3, 22, 16, 0))            # high-entropy 'text'
write("memos/memo_dated_future.txt", "Internal memo (synthetic)\n", D.now() + dt.timedelta(days=45))  # future timestamp
write("memos/old_ledger.csv", "id,value\n1,10\n", D(1970, 1, 1, 0, 0, 1))            # 1970 timestamp

print(f"Created {sum(1 for _ in OUT.rglob('*') if _.is_file())} sample files in {OUT}")
