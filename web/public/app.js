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

const VIEWS = ['view-setup', 'view-recovery', 'view-login', 'view-dash'];
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
  setStatus('ready', 'ok');
  show('view-dash');
  const [v, c] = await Promise.all([
    api('GET', '/api/vpn/status'),
    api('GET', '/api/vpn/config'),
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
}

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
  $('mac-out').textContent = r.ok ? `${r.data.iface} → ${r.data.mac}` : `error ${r.status}`;
});

refresh();
