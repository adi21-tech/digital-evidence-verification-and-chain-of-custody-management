(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  // ------------------------------------------------------------ helpers
  const b64u = {
    enc: buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
    dec: s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)).buffer; }
  };
  function toast(msg, kind = 'info') {
    const t = document.createElement('div'); t.className = 'toast ' + kind; t.textContent = msg;
    $('#toasts').appendChild(t); setTimeout(() => t.remove(), 6000);
  }
  async function send(url, opts) {
    const r = await fetch(url, opts);
    let data = {}; try { data = await r.json(); } catch (e) { /* not json */ }
    return { ok: r.ok, status: r.status, data };
  }
  const postJSON = (url, body) => send(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
  function friendly(e) {
    if (e.name === 'NotAllowedError') return 'Fingerprint cancelled, timed out or not recognised.';
    if (e.name === 'SecurityError') return 'Open the app at http://localhost:5000 (not an IP address).';
    if (e.name === 'InvalidStateError') return 'This fingerprint credential is already registered.';
    return e.message || String(e);
  }

  // ------------------------------------------------------------ fingerprint (WebAuthn)
  async function fingerprint(purpose) {
    const o = await postJSON('/api/webauthn/login/options', { purpose });
    if (!o.ok) throw new Error(o.data.error || 'Could not start fingerprint check');
    const pk = o.data;
    pk.challenge = b64u.dec(pk.challenge);
    pk.allowCredentials = pk.allowCredentials.map(c => ({ ...c, id: b64u.dec(c.id) }));
    let cred;
    try { cred = await navigator.credentials.get({ publicKey: pk }); }
    catch (e) { await postJSON('/api/webauthn/login/fail', { reason: e.name }); throw e; }
    const r = cred.response;
    const v = await postJSON('/api/webauthn/login/verify', {
      id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
      response: { clientDataJSON: b64u.enc(r.clientDataJSON), authenticatorData: b64u.enc(r.authenticatorData), signature: b64u.enc(r.signature) }
    });
    if (!v.ok) throw new Error(v.data.error || 'Fingerprint rejected');
    return v.data;
  }
  async function enroll(name) {
    const o = await postJSON('/api/webauthn/register/options', { name });
    if (!o.ok) throw new Error(o.data.error || 'Cannot start enrollment');
    const pk = o.data;
    pk.challenge = b64u.dec(pk.challenge); pk.user.id = b64u.dec(pk.user.id);
    const cred = await navigator.credentials.create({ publicKey: pk });
    const v = await postJSON('/api/webauthn/register/verify', {
      id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
      response: { clientDataJSON: b64u.enc(cred.response.clientDataJSON), attestationObject: b64u.enc(cred.response.attestationObject) }
    });
    if (!v.ok) throw new Error(v.data.error || 'Enrollment failed');
    return v.data;
  }
  // POST that transparently asks for a fingerprint if the 10-minute unlock has expired
  async function secure(url, body, isForm) {
    const go = () => isForm ? send(url, { method: 'POST', body }) : postJSON(url, body);
    let r = await go();
    if (r.status === 403 && r.data.error === 'fingerprint_required') {
      toast('Touch the fingerprint sensor to continue');
      await fingerprint('stepup');
      r = await go();
    }
    return r;
  }

  document.addEventListener('DOMContentLoaded', () => {
    // local time display
    $$('time[data-ts]').forEach(t => { const d = new Date(t.dataset.ts); if (!isNaN(d)) { t.title = t.dataset.ts; t.textContent = d.toLocaleString(); } });
    $$('[data-copy]').forEach(b => b.addEventListener('click', () => { navigator.clipboard.writeText(b.dataset.copy); toast('Copied', 'ok'); }));

    // ---------------- login page
    const status = $('#login-status');
    const setStatus = (m, k = '') => { if (status) { status.textContent = m; status.className = 'status ' + k; } };
    if ($('#warn-ip') && /^\d+\.\d+\.\d+\.\d+$/.test(location.hostname)) $('#warn-ip').hidden = false;
    if ($('#warn-nosupport') && !window.PublicKeyCredential) $('#warn-nosupport').hidden = false;

    const loginBtn = $('#btn-login');
    if (loginBtn) loginBtn.addEventListener('click', async () => {
      loginBtn.classList.add('busy'); setStatus('Waiting for your fingerprint…');
      try { await fingerprint('login'); setStatus('Fingerprint verified ✔', 'ok'); location.href = loginBtn.dataset.next || '/dashboard'; }
      catch (e) { setStatus(friendly(e), 'err'); }
      loginBtn.classList.remove('busy');
    });
    const firstBtn = $('#btn-enroll-first');
    if (firstBtn) firstBtn.addEventListener('click', async () => {
      const name = $('#enroll-name').value.trim(); if (!name) return setStatus('Enter your name first.', 'err');
      firstBtn.classList.add('busy'); setStatus('Scan your fingerprint to enroll…');
      try { await enroll(name); location.href = '/dashboard'; } catch (e) { setStatus(friendly(e), 'err'); }
      firstBtn.classList.remove('busy');
    });

    // ---------------- unlock page
    const unlock = $('#btn-unlock');
    if (unlock) unlock.addEventListener('click', async () => {
      unlock.classList.add('busy'); setStatus('Waiting for your fingerprint…');
      try { await fingerprint('stepup'); location.href = unlock.dataset.next; }
      catch (e) { setStatus(friendly(e), 'err'); }
      unlock.classList.remove('busy');
    });

    // ---------------- dashboard
    const staged = [];
    const renderStaged = () => {
      $('#staged').textContent = staged.length ? `${staged.length} file(s) ready: ` + staged.slice(0, 40).map(s => s.path).join(' · ') + (staged.length > 40 ? ' …' : '') : '';
      $('#btn-ingest').disabled = !staged.length;
    };
    const addFiles = list => { for (const f of list) staged.push({ file: f, path: f.webkitRelativePath || f.name, mtime: f.lastModified }); renderStaged(); };
    if ($('#in-folder')) {
      $('#pick-folder').onclick = () => $('#in-folder').click();
      $('#pick-files').onclick = () => $('#in-files').click();
      $('#in-folder').onchange = e => { addFiles(e.target.files); e.target.value = ''; };
      $('#in-files').onchange = e => { addFiles(e.target.files); e.target.value = ''; };
      $('#btn-ingest').onclick = async () => {
        const caseId = $('#case_id').value.trim() || 'CASE-001', B = 15, bar = $('#progress'), fill = $('div', bar);
        bar.hidden = false; $('#btn-ingest').disabled = true; let done = 0;
        for (let i = 0; i < staged.length; i += B) {
          const batch = staged.slice(i, i + B), fd = new FormData();
          fd.append('case_id', caseId);
          fd.append('meta', JSON.stringify(batch.map(b => ({ path: b.path, mtime: b.mtime }))));
          batch.forEach(b => fd.append('files', b.file, b.file.name));
          const r = await send('/upload', { method: 'POST', body: fd });
          if (!r.ok) { toast('Upload failed: ' + (r.data.error || r.status), 'err'); $('#btn-ingest').disabled = false; return; }
          done += batch.length; fill.style.width = (100 * done / staged.length) + '%';
        }
        toast(`Ingested ${done} file(s) – hashed with SHA-256 and logged`, 'ok'); setTimeout(() => location.reload(), 700);
      };
      $('#btn-verify-all').onclick = async () => {
        $('#btn-verify-all').disabled = true;
        const r = await postJSON('/verify-all');
        toast(r.data.tampered && r.data.tampered.length ? `TAMPERING DETECTED: ${r.data.tampered.join(', ')}` : `All ${r.data.checked} items match their recorded SHA-256`, r.data.tampered && r.data.tampered.length ? 'err' : 'ok');
        setTimeout(() => location.reload(), 1200);
      };
      const en = $('#btn-enroll');
      if (en) en.onclick = async () => {
        const name = prompt('Name of the new investigator (they will scan their own fingerprint next):'); if (!name) return;
        try { await enroll(name.trim()); toast('Fingerprint enrolled for ' + name, 'ok'); setTimeout(() => location.reload(), 900); }
        catch (e) { toast(friendly(e), 'err'); }
      };
    }

    const cf = $('#case-filter');
    if (cf) cf.onchange = () => { location.href = cf.value ? '?case=' + encodeURIComponent(cf.value) : '/dashboard'; };

    // ---------------- evidence page
    const evId = document.body.dataset.evidence;
    if (evId) {
      const out = $('#action-result');
      const show = (msg, kind) => { out.hidden = false; out.className = 'alert ' + kind; out.textContent = msg; };
      $('[data-act=verify]').onclick = async () => {
        const r = await secure(`/evidence/${evId}/verify`, {});
        if (r.data.ok) show('✔ MATCH – the stored file still has the SHA-256 recorded at ingest.', 'ok');
        else show('✖ MISMATCH – the file was altered after ingest. Recorded ' + r.data.expected.slice(0, 16) + '…, now ' + (r.data.computed || 'MISSING').slice(0, 16) + '…', 'bad');
        setTimeout(() => location.reload(), 1800);
      };
      $('#copy-file').onchange = async e => {
        const f = e.target.files[0]; if (!f) return; const fd = new FormData(); fd.append('file', f);
        const r = await secure(`/evidence/${evId}/verify-copy`, fd, true);
        show(r.data.ok ? '✔ This copy is identical to the recorded evidence (SHA-256 match).' : '✖ This copy is DIFFERENT from the recorded evidence (SHA-256 mismatch).', r.data.ok ? 'ok' : 'bad');
        setTimeout(() => location.reload(), 2500);
      };
      const tf = $('#transfer-form');
      if (tf) tf.onsubmit = async e => {
        e.preventDefault();
        const r = await secure(`/evidence/${evId}/transfer`, { to: tf.to.value, reason: tf.reason.value });
        if (r.ok) { show('Custody transferred to ' + r.data.custodian, 'ok'); setTimeout(() => location.reload(), 1200); } else show(r.data.error || 'Transfer failed', 'bad');
      };
      const tm = $('[data-act=tamper]');
      if (tm) tm.onclick = async () => {
        if (!confirm('DEMO: append one byte to the stored copy of this synthetic file?')) return;
        const r = await secure(`/evidence/${evId}/demo-tamper`, {});
        show(r.ok ? 'Sample file altered. Now click “Verify integrity” to watch the detector catch it.' : 'Failed', r.ok ? 'warn' : 'bad');
      };
    }

    // ---------------- audit page
    const vc = $('#btn-verify-chain');
    if (vc) vc.onclick = async () => {
      const r = await postJSON('/api/audit/verify');
      toast(r.data.valid ? `Chain valid – ${r.data.entries} entries, no tampering` : `CHAIN BROKEN at entry #${r.data.broken_at}: ${r.data.reason}`, r.data.valid ? 'ok' : 'err');
      setTimeout(() => location.reload(), 1200);
    };
    const flt = $('#audit-filter');
    if (flt) flt.onchange = () => $$('#audit-body tr').forEach(tr => tr.hidden = flt.value && tr.dataset.action !== flt.value);
  });
})();
