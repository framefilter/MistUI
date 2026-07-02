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
  return { ok: res.ok, status: res.status, data };
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

// --- flows ---

async function refresh() {
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
    show('view-wizard');
    wizardStep(1);
    return;
  }
  setStatus('ready', 'ok');
  show('view-dash');
  await refreshDash(wifi.ok ? wifi.data : {});
}

async function refreshDash(wifiData) {
  const [v, c, ks, mm] = await Promise.all([
    api('GET', '/api/vpn/status'),
    api('GET', '/api/vpn/config'),
    api('GET', '/api/vpn/killswitch'),
    api('GET', '/api/privacy/mac-schedule'),
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
    $('vpn-summary').textContent = 'no tunnel configured yet — import one below';
    $('vpn-summary').classList.remove('hidden');
    $('vpn-import-details').open = true;
  }
  if (ks.ok) $('killswitch').checked = !!ks.data.enabled;
  if (mm.ok) $('mac-mode').value = mm.data.mode;

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

// --- captive portal (§5.1) ---

async function checkPortal(prefix) {
  const p = await api('GET', '/api/net/portal');
  const box = $(prefix + '-portal');
  if (!p.ok || !box) return p;
  if (p.data.captive) {
    box.classList.remove('hidden');
    const link = $(prefix + '-portal-link');
    // A hijack portal with no redirect URL still triggers on any http page.
    link.href = p.data.portalUrl || 'http://neverssl.com';
    // The kill switch blocks exactly the direct traffic a sign-in needs —
    // §5.1 portal mode. Tell the user instead of failing mysteriously.
    const ks = await api('GET', '/api/vpn/killswitch');
    if (ks.ok && ks.data.enabled) {
      box.querySelector('.warn-text').textContent =
        'Sign-in required — but the kill switch is blocking it. ' +
        'Turn the kill switch off, sign in, then turn it back on.';
    }
  } else {
    box.classList.add('hidden');
  }
  return p;
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
  if (!r.ok) alert('could not save MAC schedule');
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
  $('mac-out').textContent = r.ok ? `uplink MAC → ${r.data.mac}` : (r.data.error || `error ${r.status}`);
});

refresh();
