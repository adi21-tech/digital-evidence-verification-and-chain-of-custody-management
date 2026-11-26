(function () {
  const form = document.getElementById("vd-form");
  const out = document.getElementById("vd-result");
  const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined) e.textContent = x; return e; };

  function render(d) {
    out.replaceChildren();
    const cls = d.status === "VERIFIED" ? "ok" : d.status === "TAMPERED" ? "bad" : "warn";
    const msg = { VERIFIED: "✔ VERIFIED – document matches " + d.evidence,
                  TAMPERED: "✘ TAMPERED – document does not match " + d.evidence,
                  NOT_FOUND: "? NOT FOUND – this document is not in the vault" }[d.status];
    out.append(el("div", "vd-banner " + cls, msg));
    if (d.expected) out.append(el("p", "vd-hash", "Recorded SHA-256: " + d.expected));
    out.append(el("p", "vd-hash", "Uploaded SHA-256: " + d.computed));
    if (!d.blocks || !d.blocks.length) return;

    const chain = el("div", "vd-chain");
    d.blocks.forEach((b, i) => {
      if (i > 0) {
        const broken = d.blocks[i - 1].id === d.tampered_block;
        const link = el("div", "vd-link" + (broken ? " broken" : ""));
        link.append(el("span", "", broken ? "✕" : "→"));
        if (broken) link.append(el("small", "", "link broken: hash mismatch"));
        chain.append(link);
      }
      const blk = el("div", "vd-block" + (b.is_target ? (d.status === "TAMPERED" ? " bad" : " ok") : ""));
      blk.append(el("b", "", "Block #" + b.id), el("div", "", b.action), el("small", "", b.actor),
                 el("small", "", "prev: " + b.prev_hash + "…"), el("small", "", "hash: " + b.entry_hash + "…"));
      if (b.is_target) blk.append(el("em", "", d.status === "TAMPERED" ? "tampered block" : "matching block"));
      chain.append(blk);
    });
    out.append(chain);
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const file = document.getElementById("vd-file").files[0];
    if (!file) { out.replaceChildren(el("p", "", "Choose a document first.")); return; }
    const fd = new FormData(); fd.append("file", file);
    try {
      const r = await fetch("/verify-documents/check", { method: "POST", body: fd });
      const d = await r.json();
      if (!r.ok) {
        out.replaceChildren(el("p", "vd-banner warn",
          d.error === "fingerprint_required" ? "Fingerprint expired. Reload this page and scan again." : (d.error || "Error")));
        return;
      }
      render(d);
    } catch (e) { out.replaceChildren(el("p", "vd-banner warn", "Could not reach the server.")); }
  });
})();