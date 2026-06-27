// MistUI walking-skeleton SPA. Vanilla ES modules, no build step — small
// enough that a framework would cost more than it saves at this stage.
// We may adopt/adapt the BubbleUI Svelte app later; this proves the API.

const $ = (id) => document.getElementById(id);

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

function setStatus(label, kind) {
  const el = $('status');
  el.textContent = label;
  el.className = 'pill' + (kind ? ' ' + kind : '');
}

async function refresh() {
  const h = await api('GET', '/api/health');
  if (!h.ok) { setStatus('offline', 'err'); return; }
  setStatus(h.data.provisioned ? 'ready' : 'setup needed', h.data.provisioned ? 'ok' : 'warn');

  const s = await api('GET', '/api/vpn/status');
  if (s.ok) {
    $('vpn-status').textContent = s.data.up ? (s.data.detail || 'connected') : 'disconnected';
  } else {
    $('vpn-status').textContent = 'login required';
  }
}

$('vpn-up').addEventListener('click', async () => {
  const r = await api('POST', '/api/vpn/up');
  $('vpn-status').textContent = r.ok ? `up (${r.data.iface})` : `error ${r.status}`;
});

$('vpn-down').addEventListener('click', async () => {
  const r = await api('POST', '/api/vpn/down');
  $('vpn-status').textContent = r.ok ? `down (${r.data.iface})` : `error ${r.status}`;
});

$('roll-mac').addEventListener('click', async () => {
  const r = await api('POST', '/api/privacy/roll-mac');
  $('mac-out').textContent = r.ok ? `${r.data.iface} → ${r.data.mac}` : `error ${r.status}`;
});

refresh();
