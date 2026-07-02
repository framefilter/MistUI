// MistUI SPA. Vanilla ES modules, no build step — small enough that a
// framework would cost more than it saves at this stage.
//
// Auth model: WebAuthn passkey (or the one-time recovery code) is the only
// way in. The Go []byte JSON convention is standard base64; WebAuthn
// identifiers travel as base64url.

const $ = (id) => document.getElementById(id);

// --- encoding helpers ---

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64urlToBuf = (s) => {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(std + '='.repeat((4 - (std.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};
const bufToB64url = (buf) =>
  b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Auth endpoints legitimately return 401 as part of their flow; every other
// 401 means the session lapsed (idle timeout), so we bounce to the lock
// screen instead of showing a cryptic error.
const AUTH_PATHS = ['/api/login', '/api/register', '/api/session'];

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (res.status === 401 && !AUTH_PATHS.some((p) => path.startsWith(p))) {
    sessionLapsed();
  }
  return { ok: res.ok, status: res.status, data };
}

let lapsing = false;
function sessionLapsed() {
  if (lapsing) return; // avoid a storm from concurrent calls
  lapsing = true;
  setStatus('locked', 'warn');
  $('lock').classList.add('hidden');
  show('view-login');
  say('login-out', 'Session timed out — unlock again to continue.');
  setTimeout(() => { lapsing = false; }, 1000);
}

// --- view plumbing ---

const VIEWS = ['view-setup', 'view-recovery', 'view-login', 'view-wizard', 'view-dash'];
function show(view) {
  for (const v of VIEWS) $(v).classList.toggle('hidden', v !== view);
}

function setStatus(label, kind) {
  const el = $('status');
  el.textContent = label;
  el.className = 'pill' + (kind ? ' ' + kind : '');
}

function say(id, msg) {
  const el = $(id);
  el.textContent = msg;
  el.classList.remove('hidden');
}

// --- WebAuthn ceremonies ---

async function register() {
  const begin = await api('POST', '/api/register/begin');
  if (!begin.ok) throw new Error(`begin: ${begin.status}`);
  const o = begin.data;
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { id: o.rpId, name: 'MistUI' },
      user: {
        id: b64urlToBuf(o.user.id),
        name: o.user.name,
        displayName: o.user.name,
      },
      challenge: b64urlToBuf(o.challenge),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256 only
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      attestation: 'none', // trust-on-first-use: the server ignores it anyway
    },
  });
  const finish = await api('POST', '/api/register/finish', {
    clientDataJSON: b64(cred.response.clientDataJSON),
    attestationObject: b64(cred.response.attestationObject),
  });
  if (!finish.ok) throw new Error(`finish: ${finish.status}`);
  return finish.data; // { registered, credentialId, recoveryCode? }
}

async function loginPasskey() {
  const begin = await api('POST', '/api/login/begin');
  if (!begin.ok) throw new Error(`begin: ${begin.status}`);
  const o = begin.data;
  const cred = await navigator.credentials.get({
    publicKey: {
      rpId: o.rpId,
      challenge: b64urlToBuf(o.challenge),
      allowCredentials: (o.credentialIds || []).map((id) => ({
        type: 'public-key',
        id: b64urlToBuf(id),
      })),
      userVerification: 'preferred',
    },
  });
  const finish = await api('POST', '/api/login/finish', {
    credentialId: bufToB64url(cred.rawId),
    authenticatorData: b64(cred.response.authenticatorData),
    clientDataJSON: b64(cred.response.clientDataJSON),
    signature: b64(cred.response.signature),
  });
  if (!finish.ok) throw new Error(`finish: ${finish.status}`);
}

// stepUp runs the fresh-assertion ceremony (§4.2): one passkey touch, one
// destructive action.
async function stepUp() {
  const begin = await api('POST', '/api/stepup/begin');
  if (!begin.ok) throw new Error(`step-up begin: ${begin.status}`);
  const o = begin.data;
  const cred = await navigator.credentials.get({
    publicKey: {
      rpId: o.rpId,
      challenge: b64urlToBuf(o.challenge),
      allowCredentials: (o.credentialIds || []).map((id) => ({
        type: 'public-key',
        id: b64urlToBuf(id),
      })),
      userVerification: 'preferred',
    },
  });
  const finish = await api('POST', '/api/stepup/finish', {
    credentialId: bufToB64url(cred.rawId),
    authenticatorData: b64(cred.response.authenticatorData),
    clientDataJSON: b64(cred.response.clientDataJSON),
    signature: b64(cred.response.signature),
  });
  if (!finish.ok) throw new Error(`step-up finish: ${finish.status}`);
}

// withStepUp calls a destructive endpoint, satisfying the 428 contract:
// touch first, and if the credit lapsed anyway (expiry, daemon restart),
// touch once more and retry.
async function withStepUp(method, path, body) {
  await stepUp();
  let r = await api(method, path, body);
  if (r.status === 428) {
    await stepUp();
    r = await api(method, path, body);
  }
  return r;
}

// --- flows ---

async function refresh() {
  $('lock').classList.add('hidden'); // shown only once authenticated
  const h = await api('GET', '/api/health');
  if (!h.ok) { setStatus('offline', 'err'); return; }

  if (!h.data.provisioned) {
    setStatus('setup needed', 'warn');
    show('view-setup');
    return;
  }
  const s = await api('GET', '/api/session');
  if (!s.data.authenticated) {
    setStatus('locked', 'warn');
    show('view-login');
    return;
  }
  // Authenticated: wizard until the travel network exists, then dashboard.
  const wifi = await api('GET', '/api/wifi/status');
  if (wifi.ok && !wifi.data.apEnabled) {
    setStatus('setup', 'warn');
    $('lock').classList.remove('hidden');
    show('view-wizard');
    wizardStep(1);
    return;
  }
  setStatus('ready', 'ok');
  $('lock').classList.remove('hidden');
  show('view-dash');
  await refreshDash(wifi.ok ? wifi.data : {});
}

async function refreshDash(wifiData) {
  const [v, c, ks, mm, mp, dn] = await Promise.all([
    api('GET', '/api/vpn/status'),
    api('GET', '/api/vpn/config'),
    api('GET', '/api/vpn/killswitch'),
    api('GET', '/api/privacy/mac-schedule'),
    api('GET', '/api/privacy/mac-profile'),
    api('GET', '/api/dns'),
  ]);
  $('vpn-status').textContent = v.ok
    ? (v.data.up ? (v.data.detail || 'connected') : 'disconnected')
    : 'status unavailable';
  if (c.ok && c.data.configured) {
    const s = c.data.summary || {};
    $('vpn-summary').textContent =
      `configured — endpoint ${(s.endpoints || []).join(', ') || 'n/a'}; ` +
      `tunnel routes ${(s.allowedIPs || []).join(', ') || 'n/a'}`;
    $('vpn-summary').classList.remove('hidden');
    $('vpn-import-details').open = false;
  } else if (c.ok) {
    $('vpn-summary').textContent = 'no tunnel configured yet';
    $('vpn-summary').classList.remove('hidden');
  }
  if (ks.ok) $('killswitch').checked = !!ks.data.enabled;
  if (dn.ok) renderDNS(dn.data);
  refreshMaint();
  if (mm.ok) $('mac-mode').value = mm.data.mode;
  if (mp.ok) {
    const sel = $('mac-profile');
    sel.replaceChildren(...(mp.data.profiles || []).map((p) => {
      const o = document.createElement('option');
      o.value = p.key;
      o.textContent = p.label;
      return o;
    }));
    sel.value = mp.data.current;
  }

  const w = wifiData.apEnabled !== undefined
    ? { ok: true, data: wifiData }
    : await api('GET', '/api/wifi/status');
  if (w.ok) {
    const d = w.data;
    const uplink = d.uplinkSsid
      ? `uplink “${d.uplinkSsid}” ${d.uplinkUp ? `up (${d.uplinkIp || 'no ip'})` : 'down'}`
      : 'no wireless uplink configured';
    $('net-summary').textContent = `travel network “${d.apSsid}” · ${uplink}`;
    if (d.uplinkUp) checkPortal('dash');
  }
}

// --- encrypted DNS (§5 item 5) ---

function renderDNS(d) {
  $('dns-toggle').checked = !!d.enabled;
  $('dns-warning').classList.toggle('hidden', !!d.enabled);
  const sel = $('dns-provider');
  sel.replaceChildren(...(d.providers || []).map((p) => {
    const o = document.createElement('option');
    o.value = p.key;
    o.textContent = p.label;
    return o;
  }));
  sel.value = d.provider;
  const st = d.stats || {};
  $('dns-status').textContent = !d.enabled
    ? 'off — devices use whatever DNS the current network hands out'
    : st.queries
      ? `${st.queries} lookups encrypted` +
        (st.failures ? `, ${st.failures} failed (last: ${st.lastError || 'unknown'})` : '')
      : 'on — no lookups yet';
}

async function refreshDNS() {
  const r = await api('GET', '/api/dns');
  if (r.ok) renderDNS(r.data);
}

$('dns-toggle').addEventListener('change', async (e) => {
  const r = await api('POST', '/api/dns', { enabled: e.target.checked });
  if (!r.ok) {
    e.target.checked = !e.target.checked;
    alert(r.data.raw || 'encrypted DNS change failed');
  }
  await refreshDNS();
});

$('dns-provider').addEventListener('change', async (e) => {
  const r = await api('POST', '/api/dns/provider', { provider: e.target.value });
  if (!r.ok) alert('could not switch DNS resolver');
});

// --- captive portal (§5.1) ---
//
// mistd runs the portal state machine itself: it scouts new uplinks,
// pauses the protections a sign-in needs punched through, and restores
// them (plus the VPN) once real connectivity appears. The UI's job is to
// show that state honestly and offer the manual pause/restore levers.

let portalTimer = null;

async function checkPortal(prefix) {
  const p = await api('GET', '/api/net/portal');
  const box = $(prefix + '-portal');
  if (!p.ok || !box) return p;
  const d = p.data;
  $(prefix + '-portal-note').textContent = d.note || '';
  const paused = d.pause && d.pause.active;
  if (d.captive || paused) {
    box.classList.remove('hidden');
    // A hijack portal with no redirect URL still triggers on any http page.
    $(prefix + '-portal-link').href = d.portalUrl || 'http://neverssl.com';
    const txt = box.querySelector('.warn-text');
    if (paused) {
      const mins = Math.max(1, Math.round((d.pause.secondsLeft || 0) / 60));
      txt.textContent =
        'Sign-in required. Protections are paused so the sign-in can go ' +
        `through — everything restores automatically once you're online ` +
        `(or in ~${mins} min).`;
      $(prefix + '-portal-pause').classList.add('hidden');
      $(prefix + '-portal-restore').classList.remove('hidden');
      watchPortalPause(prefix);
    } else {
      txt.textContent =
        'Sign-in required. If the sign-in page won’t load, pause ' +
        'protections first — they restore themselves after.';
      $(prefix + '-portal-pause').classList.remove('hidden');
      $(prefix + '-portal-restore').classList.add('hidden');
    }
  } else {
    box.classList.add('hidden');
  }
  return p;
}

// While a pause is active, poll so the countdown stays honest and the UI
// snaps back the moment the machine restores protections.
function watchPortalPause(prefix) {
  if (portalTimer) return;
  portalTimer = setInterval(async () => {
    const p = await checkPortal(prefix);
    const still = p.ok && p.data.pause && p.data.pause.active;
    if (!still) {
      clearInterval(portalTimer);
      portalTimer = null;
      if (p.ok && p.data.online && prefix === 'wiz') wizardStep(3);
      if (prefix === 'dash') refresh(); // toggles changed under us
    }
  }, 5000);
}

for (const prefix of ['wiz', 'dash']) {
  $(prefix + '-portal-pause').addEventListener('click', async () => {
    const r = await api('POST', '/api/net/portal-mode', { active: true });
    if (!r.ok) alert('could not pause protections');
    await checkPortal(prefix);
  });
  $(prefix + '-portal-restore').addEventListener('click', async () => {
    const r = await api('POST', '/api/net/portal-mode', { active: false });
    if (!r.ok) alert('could not restore protections');
    if (prefix === 'dash') { await refresh(); } else { await checkPortal(prefix); }
  });
}

// --- first-boot wizard ---

function wizardStep(n) {
  $('wiz-step').textContent = n;
  for (const i of [1, 2, 3]) $('wiz-' + i).classList.toggle('hidden', i !== n);
}

$('wiz-ap-save').addEventListener('click', async () => {
  const r = await api('POST', '/api/wifi/ap', {
    ssid: $('wiz-ap-ssid').value.trim(),
    key: $('wiz-ap-key').value,
  });
  if (!r.ok) { alert(r.data.error || 'could not create network'); return; }
  wizardStep(2);
});

$('wiz-scan').addEventListener('click', async () => {
  $('wiz-networks').textContent = 'scanning…';
  const r = await api('POST', '/api/wifi/scan');
  if (!r.ok) { $('wiz-networks').textContent = r.data.error || 'scan failed'; return; }
  const list = document.createElement('div');
  for (const n of (r.data.networks || []).sort((a, b) => b.signal - a.signal)) {
    const b = document.createElement('button');
    b.className = 'ghost net-item';
    b.textContent = `${n.ssid}  (${n.signal} dBm${n.encryption === 'none' ? ', open' : ''})`;
    b.addEventListener('click', () => {
      $('wiz-join-ssid').textContent = n.ssid;
      $('wiz-join').classList.remove('hidden');
      $('wiz-join-key').value = '';
    });
    list.appendChild(b);
  }
  $('wiz-networks').replaceChildren(list);
});

$('wiz-join-go').addEventListener('click', async () => {
  const ssid = $('wiz-join-ssid').textContent;
  const r = await api('POST', '/api/wifi/uplink', { ssid, key: $('wiz-join-key').value });
  if (!r.ok) { say('wiz-uplink-out', r.data.error || 'join failed'); return; }
  say('wiz-uplink-out', `joining “${ssid}”…`);
  for (let i = 0; i < 30; i++) {
    await new Promise((res) => setTimeout(res, 2000));
    const s = await api('GET', '/api/wifi/status');
    if (s.ok && s.data.uplinkUp) {
      say('wiz-uplink-out', `connected (${s.data.uplinkIp || 'no ip yet'})`);
      const p = await checkPortal('wiz');
      if (p.ok && p.data.online) wizardStep(3);
      return; // if captive, the portal box is showing; recheck advances
    }
  }
  say('wiz-uplink-out', 'still not connected — wrong password, or try again');
});

$('wiz-portal-recheck').addEventListener('click', async () => {
  const p = await checkPortal('wiz');
  if (p.ok && p.data.online) wizardStep(3);
});

$('wiz-skip-uplink').addEventListener('click', () => wizardStep(3));

$('wiz-vpn-import').addEventListener('click', async () => {
  const config = $('wiz-vpn-conf').value.trim();
  if (!config) return;
  const r = await api('POST', '/api/vpn/import', { config });
  if (!r.ok) { say('wiz-vpn-out', r.data.error || `import failed (${r.status})`); return; }
  await refresh();
});

$('wiz-skip-vpn').addEventListener('click', () => refresh());

// --- dashboard controls ---

$('lock').addEventListener('click', async () => {
  await api('POST', '/api/logout');
  $('lock').classList.add('hidden');
  setStatus('locked', 'warn');
  show('view-login');
});

$('dash-portal-recheck').addEventListener('click', () => checkPortal('dash'));

$('killswitch').addEventListener('change', async (e) => {
  const r = await api('POST', '/api/vpn/killswitch', { enabled: e.target.checked });
  if (!r.ok) {
    e.target.checked = !e.target.checked;
    alert('kill switch change failed');
  }
});

$('mac-mode').addEventListener('change', async (e) => {
  const r = await api('POST', '/api/privacy/mac-schedule', { mode: e.target.value });
  if (!r.ok) alert('could not save identity schedule');
});

$('mac-profile').addEventListener('change', async (e) => {
  const r = await api('POST', '/api/privacy/mac-profile', { profile: e.target.value });
  if (!r.ok) alert('could not save identity profile');
});

$('setup-create').addEventListener('click', async () => {
  try {
    const out = await register();
    if (out.recoveryCode) {
      $('recovery-code').textContent = out.recoveryCode;
      show('view-recovery');
      setStatus('save your code', 'warn');
    } else {
      await refresh();
    }
  } catch (e) {
    say('setup-out', `passkey creation failed: ${e.message || e}`);
  }
});

$('recovery-saved').addEventListener('click', () => {
  $('recovery-code').textContent = '';
  refresh();
});

$('login-passkey').addEventListener('click', async () => {
  try {
    await loginPasskey();
    await refresh();
  } catch (e) {
    say('login-out', `unlock failed: ${e.message || e}`);
  }
});

$('login-recovery').addEventListener('click', async () => {
  const code = $('recovery-input').value.trim();
  if (!code) return;
  const r = await api('POST', '/api/login/recovery', { code });
  if (!r.ok) {
    say('login-out', 'recovery code rejected (it may already have been used)');
    return;
  }
  $('recovery-input').value = '';
  await refresh();
});

// --- maintenance (§5 item 7) ---

async function refreshMaint() {
  const r = await api('GET', '/api/maintenance/board');
  if (!r.ok) return;
  const b = r.data.board || {};
  $('maint-board').textContent =
    `${b.model || 'unknown device'} · OpenWrt ${b.release || '?'} (${b.target || '?'})`;
}

$('regen-recovery').addEventListener('click', async () => {
  try {
    const r = await withStepUp('POST', '/api/recovery/regenerate');
    if (!r.ok) { say('regen-out', `failed (${r.status})`); return; }
    say('regen-out',
      `${r.data.recoveryCode}\n\nWrite this down now — it replaces the old ` +
      `code, is shown only once, and works once.`);
  } catch (e) {
    say('regen-out', `passkey confirmation failed: ${e.message || e}`);
  }
});

$('fw-upload').addEventListener('click', async () => {
  const file = $('fw-file').files[0];
  if (!file) { say('fw-out', 'choose a sysupgrade image first'); return; }
  say('fw-out', `uploading ${file.name} (${(file.size / 1048576).toFixed(1)} MB)…`);
  $('fw-flash').classList.add('hidden');
  const res = await fetch('/api/maintenance/firmware', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: file,
  });
  if (res.status === 401) { sessionLapsed(); return; }
  let data = {};
  try { data = await res.json(); } catch { /* keep {} */ }
  if (!res.ok) {
    say('fw-out', `image rejected: ${data.error || res.status}`);
    return;
  }
  say('fw-out', 'image verified for this device — ready to flash');
  $('fw-flash').classList.remove('hidden');
});

$('fw-flash').addEventListener('click', async () => {
  try {
    const r = await withStepUp('POST', '/api/maintenance/firmware/flash');
    if (!r.ok) { say('fw-out', `flash refused: ${r.data.error || r.status}`); return; }
    say('fw-out', 'flashing… the router reboots itself. This page will ' +
      'reconnect when it is back (2–4 minutes). Settings are kept.');
    $('fw-flash').classList.add('hidden');
    awaitReboot('fw-out');
  } catch (e) {
    say('fw-out', `passkey confirmation failed: ${e.message || e}`);
  }
});

$('factory-reset').addEventListener('click', async () => {
  const sure = confirm(
    'Factory reset erases EVERYTHING on this router:\n\n' +
    '• all settings, Wi-Fi networks and the VPN config\n' +
    '• every passkey and the recovery code\n' +
    '• the device certificate you installed\n\n' +
    'The router reboots as freshly flashed and must be set up from ' +
    'scratch. Continue to the passkey confirmation?');
  if (!sure) return;
  try {
    const r = await withStepUp('POST', '/api/maintenance/factory-reset');
    if (!r.ok) { say('reset-out', `reset refused (${r.status})`); return; }
    say('reset-out', 'resetting… the router is wiping itself and will ' +
      'reboot with its default network. This page will go dark.');
  } catch (e) {
    say('reset-out', `passkey confirmation failed: ${e.message || e}`);
  }
});

// awaitReboot polls health until the device answers again, then reloads.
async function awaitReboot(outId) {
  for (let i = 0; i < 60; i++) {
    await new Promise((res) => setTimeout(res, 5000));
    try {
      const h = await api('GET', '/api/health');
      if (h.ok) { location.reload(); return; }
    } catch { /* still down */ }
  }
  say(outId, 'still unreachable — check the router and reload this page.');
}

// ifup/ifdown are asynchronous in netifd — poll status until it settles.
async function pollVpnStatus(wantUp, tries = 10) {
  for (let i = 0; i < tries; i++) {
    const v = await api('GET', '/api/vpn/status');
    if (v.ok && v.data.up === wantUp) {
      $('vpn-status').textContent = wantUp ? (v.data.detail || 'connected') : 'disconnected';
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  $('vpn-status').textContent = wantUp
    ? 'still connecting… (check again shortly)'
    : 'still disconnecting…';
}

$('vpn-up').addEventListener('click', async () => {
  const r = await api('POST', '/api/vpn/up');
  if (!r.ok) { $('vpn-status').textContent = `error ${r.status}`; return; }
  $('vpn-status').textContent = 'connecting…';
  await pollVpnStatus(true);
});

$('vpn-down').addEventListener('click', async () => {
  const r = await api('POST', '/api/vpn/down');
  if (!r.ok) { $('vpn-status').textContent = `error ${r.status}`; return; }
  $('vpn-status').textContent = 'disconnecting…';
  await pollVpnStatus(false);
});

$('vpn-import').addEventListener('click', async () => {
  const config = $('vpn-conf').value.trim();
  if (!config) return;
  const r = await api('POST', '/api/vpn/import', { config });
  if (!r.ok) {
    say('vpn-import-out', r.data.error || `import failed (${r.status})`);
    return;
  }
  $('vpn-conf').value = '';
  $('vpn-import-out').classList.add('hidden');
  await refresh();
});

$('roll-mac').addEventListener('click', async () => {
  const r = await api('POST', '/api/privacy/roll-mac');
  if (!r.ok) { $('mac-out').textContent = r.data.error || `error ${r.status}`; return; }
  const id = r.data.identity || {};
  $('mac-out').textContent = id.hostname
    ? `now appearing as “${id.hostname}” · ${id.mac}`
    : `uplink MAC → ${id.mac}`;
});

refresh();
