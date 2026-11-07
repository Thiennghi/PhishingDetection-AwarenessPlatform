'use strict';
let adminToken, allReports = [], activeFilter = 'pending';
const adminEl = id => document.getElementById(id);
const show = (id, on = true) => adminEl(id).classList.toggle('hidden', !on);

function setStatus(message, kind = 'info') {
  const el = adminEl('adminStatus');
  el.textContent = message || '';
  el.dataset.kind = message ? kind : '';
}
async function readJson(r) {
  try { return await r.json(); } catch (e) { throw new Error('The server returned an unexpected response (HTTP ' + r.status + '). Check PHP errors on the host.'); }
}
async function adminSession() {
  const r = await fetch('csrf.php', { credentials: 'same-origin', headers: { Accept: 'application/json' } });
  const d = await readJson(r);
  if (!r.ok || !d.token) throw new Error(d.message || 'Session unavailable. Check your PHP server configuration.');
  adminToken = d.token;
}
async function adminRequest(fields) {
  const options = { credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (fields) {
    options.method = 'POST';
    options.headers['X-CSRF-Token'] = adminToken;
    options.body = new FormData();
    Object.entries(fields).forEach(([k, v]) => options.body.append(k, v));
  }
  const r = await fetch('admin_reports.php', options);
  const d = await readJson(r);
  if (!r.ok || !d.success) { const err = new Error(d.message || 'Request failed.'); err.status = r.status; throw err; }
  return d;
}
function showLogin(message, kind) {
  show('reviewPanel', false); show('setupPanel', false); show('resetPanel', false); show('loginPanel', true);
  if (message) setStatus(message, kind);
}

/* ---------- report list ---------- */
function badge(status) {
  const b = document.createElement('span');
  b.className = 'review-status status-' + status;
  b.textContent = status;
  return b;
}
function renderCounts(counts) {
  const c = counts || { pending: 0, approved: 0, rejected: 0 };
  adminEl('statPending').textContent = c.pending;
  adminEl('statApproved').textContent = c.approved;
  adminEl('statRejected').textContent = c.rejected;
}
const NOTE_PRESETS = [
  'Verified independently: matches known phishing pattern.',
  'Could not verify the claim; insufficient evidence.',
  'Duplicate of an existing report.',
  'Legitimate site; reported in error.'
];
function buildCard(report) {
  const card = document.createElement('article');
  card.className = 'card review-card margin-top';
  const head = document.createElement('div'); head.className = 'review-head';
  const title = document.createElement('h2'); title.textContent = '#' + report.report_id + ' · ' + report.category;
  head.append(title, badge(report.status));
  const meta = document.createElement('p'); meta.className = 'muted review-meta';
  const parts = ['Submitted ' + report.created_at + ' UTC'];
  if (report.reviewed_at) parts.push('reviewed ' + report.reviewed_at + ' UTC');
  if (report.expires_at) parts.push('indicator expires ' + report.expires_at + ' UTC');
  meta.textContent = parts.join(' · ');
  const address = document.createElement('code');
  address.textContent = report.submitted_url ? report.submitted_url.replace(/^http/i, 'hxxp').replace(/\./g, '[.]') : 'Message-only report';
  const description = document.createElement('p'); description.className = 'review-desc'; description.textContent = report.description;

  const label = document.createElement('label'); label.htmlFor = 'note-' + report.report_id; label.textContent = 'Review evidence / reason';
  const note = document.createElement('textarea'); note.id = label.htmlFor; note.className = 'form-control'; note.maxLength = 1000; note.rows = 3; note.value = report.review_note || '';
  const counter = document.createElement('small'); counter.className = 'muted char-count';
  const updateCount = () => { counter.textContent = note.value.length + ' / 1000'; };
  note.addEventListener('input', updateCount); updateCount();
  const presets = document.createElement('div'); presets.className = 'flags';
  NOTE_PRESETS.forEach(text => {
    const chip = document.createElement('button'); chip.type = 'button'; chip.className = 'pill'; chip.textContent = text.replace(/\.$/, '');
    chip.addEventListener('click', () => { note.value = text; updateCount(); note.focus(); });
    presets.appendChild(chip);
  });

  const buttons = document.createElement('div'); buttons.className = 'button-row margin-top';
  for (const action of ['approve', 'reject']) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = action === 'approve' ? 'btn-primary' : 'btn-secondary';
    button.textContent = action === 'approve' ? 'Approve URL for 30 days' : 'Reject / revoke';
    button.disabled = action === 'approve' && !report.submitted_url;
    if (button.disabled) button.title = 'Message-only reports cannot become URL indicators.';
    button.addEventListener('click', async () => {
      if (note.value.trim().length < 5) { setStatus('Add a review note of at least 5 characters.', 'error'); note.focus(); return; }
      Array.from(buttons.children).forEach(b => b.disabled = true);
      try {
        const result = await adminRequest({ action, report_id: report.report_id, note: note.value });
        await refreshReviews();
        setStatus(result.message + ' (#' + report.report_id + ')', 'success');
      } catch (e) {
        if (e.status === 401 || e.status === 403) { showLogin('Your session expired. Please sign in again.', 'error'); return; }
        setStatus(e.message, 'error');
        Array.from(buttons.children).forEach((b, i) => b.disabled = i === 0 && !report.submitted_url);
      }
    });
    buttons.appendChild(button);
  }
  card.append(head, meta, address, description, label, note, counter, presets, buttons);
  return card;
}
function renderList() {
  const list = adminEl('reviewList');
  list.replaceChildren();
  const q = adminEl('reportSearch').value.trim().toLowerCase();
  const rows = allReports.filter(r => (activeFilter === 'all' || r.status === activeFilter) &&
    (!q || ('#' + r.report_id + ' ' + r.category + ' ' + r.description + ' ' + (r.submitted_url || '')).toLowerCase().includes(q)));
  adminEl('listSummary').textContent = rows.length + ' report' + (rows.length === 1 ? '' : 's') + ' shown · up to 100 latest loaded, pending first. Submitted links stay inactive.';
  if (!rows.length) {
    const empty = document.createElement('div'); empty.className = 'card admin-empty';
    empty.textContent = allReports.length ? 'No reports match this filter.' : 'No community reports yet.';
    list.appendChild(empty); return;
  }
  rows.forEach(r => list.appendChild(buildCard(r)));
}
async function refreshReviews() {
  const data = await adminRequest();
  show('loginPanel', false); show('setupPanel', false); show('resetPanel', false); show('reviewPanel', true);
  allReports = data.reports || [];
  const counts = data.counts || allReports.reduce((a, r) => (a[r.status] = (a[r.status] || 0) + 1, a), {});
  renderCounts(counts);
  // If nothing is pending, show everything so the page is never confusingly empty.
  if (activeFilter === 'pending' && !(counts.pending > 0) && allReports.length) setFilter('all', false);
  renderList();
}
function setFilter(filter, render = true) {
  activeFilter = filter;
  document.querySelectorAll('[data-filter]').forEach(b => { const on = b.dataset.filter === filter; b.classList.toggle('active', on); b.setAttribute('aria-selected', on); });
  if (render) renderList();
}
document.querySelectorAll('[data-filter]').forEach(b => b.addEventListener('click', () => setFilter(b.dataset.filter)));
adminEl('reportSearch').addEventListener('input', renderList);
adminEl('refreshReports').addEventListener('click', async () => {
  setStatus('Refreshing…');
  try { await refreshReviews(); setStatus('Reports refreshed.', 'success'); }
  catch (e) { if (e.status === 401 || e.status === 403) showLogin('Your session expired. Please sign in again.', 'error'); else setStatus(e.message, 'error'); }
});

/* ---------- show/hide password + strength ---------- */
document.querySelectorAll('[data-toggle-password]').forEach(box => box.addEventListener('change', () => {
  box.dataset.togglePassword.split(',').forEach(id => { adminEl(id).type = box.checked ? 'text' : 'password'; });
}));
function strength(pw) {
  let score = 0;
  if (pw.length >= 12) score++; if (pw.length >= 16) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++; if (/[^A-Za-z0-9]/.test(pw)) score++;
  return Math.min(score, 4);
}
adminEl('setupPassword').addEventListener('input', e => {
  const pw = e.target.value, s = pw ? strength(pw) : 0;
  adminEl('setupStrengthBar').style.width = (s * 25) + '%';
  adminEl('setupStrengthBar').dataset.level = s;
  adminEl('setupStrengthText').textContent = pw ? (pw.length < 12 ? 'Needs at least 12 characters' : ['Weak', 'Fair', 'Good', 'Strong', 'Very strong'][s]) : '';
});

/* ---------- first-time setup (localhost directly, hosted with one-time key) ---------- */
async function checkAdminSetup() {
  const r = await fetch('admin_setup.php', { credentials: 'same-origin', headers: { Accept: 'application/json' }, cache: 'no-store' });
  const d = await readJson(r);
  if (!r.ok || !d.success) throw new Error(d.message || 'Could not check administrator setup.');
  if (d.configured) { show('setupPanel', false); show('loginPanel', true); return true; }
  show('setupPanel', true); show('loginPanel', false);
  const hint = adminEl('setupHint'), form = adminEl('adminSetup');
  if (d.needs_key) {
    show('setupKeyWrap', true); adminEl('setupKey').required = !!d.key_file_present;
    if (d.key_file_present) {
      show('setupHint', false); form.querySelectorAll('input,button').forEach(el => el.disabled = false);
      setStatus('Hosted setup is unlocked. Enter your one-time setup key and choose your credentials.', 'info');
    } else {
      hint.replaceChildren();
      const lines = ['Hosted setup is locked until you create a private key file:',
        '1. Open your hosting Online File Manager (or FTP) in the folder that contains admin.html.',
        '2. Create a file named admin_setup_key.php containing: <?php return \'YOUR-RANDOM-KEY-40+-CHARACTERS\';',
        '3. Reload this page, enter the same key below and choose your credentials. The file is deleted automatically afterwards.'];
      lines.forEach((t, i) => { const p = document.createElement(i ? 'div' : 'strong'); p.textContent = t; hint.appendChild(p); });
      show('setupHint', true); form.querySelectorAll('input,button').forEach(el => el.disabled = true);
      setStatus('No administrator account is configured yet. Create the one-time key file to continue.', 'info');
    }
  } else {
    show('setupKeyWrap', false); show('setupHint', false);
    setStatus('No administrator account is configured yet. Create one below.', 'info');
  }
  return false;
}
adminEl('adminSetup').addEventListener('submit', async e => {
  e.preventDefault(); const button = e.target.querySelector('button'); button.disabled = true;
  try {
    const username = adminEl('setupUsername').value.trim(), password = adminEl('setupPassword').value, confirm = adminEl('setupConfirm').value;
    if (password.length < 12) throw new Error('Use a unique password with at least 12 characters.');
    if (password !== confirm) throw new Error('The passwords do not match.');
    const r = await fetch('admin_setup.php', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, confirm_password: confirm, setup_key: adminEl('setupKey').value }) });
    const d = await readJson(r);
    if (!r.ok || !d.success) throw new Error(d.message || 'Setup failed.');
    ['setupPassword', 'setupConfirm', 'setupKey'].forEach(id => adminEl(id).value = '');
    adminEl('username').value = username;
    show('setupPanel', false); show('loginPanel', true);
    setStatus(d.message + ' You can now sign in.', 'success');
  } catch (err) { setStatus(err.message, 'error'); } finally { button.disabled = false; }
});

/* ---------- sign in / out ---------- */
adminEl('adminLogin').addEventListener('submit', async e => {
  e.preventDefault(); const button = e.target.querySelector('button'); button.disabled = true; setStatus('Signing in…');
  try {
    await adminSession();
    await adminRequest({ action: 'login', username: adminEl('username').value, password: adminEl('password').value });
    adminEl('password').value = '';
    await adminSession(); await refreshReviews(); setStatus('Signed in.', 'success');
  } catch (err) { setStatus(err.message, 'error'); } finally { button.disabled = false; }
});
adminEl('logout').addEventListener('click', async () => {
  try {
    await adminRequest({ action: 'logout' });
    adminEl('reviewList').replaceChildren(); allReports = [];
    showLogin('Signed out.', 'success'); await adminSession();
  } catch (err) { setStatus(err.message, 'error'); }
});

/* ---------- account recovery (localhost direct, hosted with one-time key) ---------- */
adminEl('showReset').addEventListener('click', async () => {
  try {
    const r = await fetch('admin_reset.php', { credentials: 'same-origin', headers: { Accept: 'application/json' }, cache: 'no-store' });
    const d = await readJson(r);
    if (!r.ok || !d.success) throw new Error(d.message || 'Could not check recovery options.');
    show('resetPanel', true); show('setupPanel', false); show('loginPanel', false);
    setStatus(d.message, 'info');
  } catch (err) { setStatus(err.message, 'error'); }
});
adminEl('cancelReset').addEventListener('click', () => { show('resetPanel', false); show('loginPanel', true); setStatus('Account recovery cancelled.'); });
adminEl('adminReset').addEventListener('submit', async e => {
  e.preventDefault(); const button = e.target.querySelector('button'); button.disabled = true;
  try {
    const username = adminEl('resetUsername').value.trim(), password = adminEl('resetPassword').value, confirm = adminEl('resetConfirm').value, recoveryKey = adminEl('recoveryKey').value;
    if (password.length < 12) throw new Error('Use a unique password with at least 12 characters.');
    if (password !== confirm) throw new Error('The passwords do not match.');
    const r = await fetch('admin_reset.php', { method: 'POST', credentials: 'same-origin', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, confirm_password: confirm, recovery_key: recoveryKey }) });
    const d = await readJson(r);
    if (!r.ok || !d.success) throw new Error(d.message || 'Account recovery failed.');
    ['recoveryKey', 'resetPassword', 'resetConfirm'].forEach(id => adminEl(id).value = '');
    adminEl('username').value = d.username;
    show('resetPanel', false); show('loginPanel', true); setStatus(d.message, 'success');
  } catch (err) { setStatus(err.message, 'error'); } finally { button.disabled = false; }
});

(async () => {
  try {
    const configured = await checkAdminSetup();
    if (configured) {
      await adminSession();
      try { await refreshReviews(); }
      catch (e) { if (e.status === 401 || e.status === 403) { setStatus(''); } else throw e; } // not signed in yet: show login quietly
    }
  } catch (e) { setStatus(e.message, 'error'); }
})();
