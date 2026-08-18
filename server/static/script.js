let _currentFilter = '';
let _allRows = [];

function switchTab(name, btn) {
  document.querySelectorAll('.tab-panel').forEach(x => x.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(x => x.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  document.getElementById('tabTitle').textContent = btn.textContent.trim();
  if (name === 'devices' || name === 'blocked' || name === 'analytics') refreshAll();
}

function setPill(pill, severity) {
  document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
  pill.classList.add('active');
  _currentFilter = severity;
  filterRows();
}

function filterRows() {
  const q = (document.getElementById('searchInput').value || '').toLowerCase();
  document.querySelectorAll('#logBody tr').forEach(tr => {
    const sev = tr.dataset.severity || '';
    const matchFilter = !_currentFilter || sev === _currentFilter;
    const matchSearch = !q || tr.textContent.toLowerCase().includes(q);
    tr.style.display = matchFilter && matchSearch ? '' : 'none';
  });
}

async function fetchJSON(url, opts) {
  const r = await fetch(url, opts);
  return await r.json();
}

async function updateStats() {
  const data = await fetchJSON('/stats');
  document.getElementById('statTotal').textContent  = data.total || 0;
  document.getElementById('statHigh').textContent   = data.counts?.HIGH   || 0;
  document.getElementById('statMedium').textContent = data.counts?.MEDIUM || 0;
  document.getElementById('statNormal').textContent = data.counts?.NORMAL || 0;
  document.getElementById('statAuth').textContent   = data.authorized_count || 0;

  const summary = document.getElementById('severitySummary');
  if (summary) {
    const rows = [
      { label: 'High Severity', count: data.counts?.HIGH || 0 },
      { label: 'Medium Severity', count: data.counts?.MEDIUM || 0 },
      { label: 'Normal Events', count: data.counts?.NORMAL || 0 },
      { label: 'Blocked Devices', count: (data.blocked_devices || []).length },
    ];
    summary.innerHTML = rows.map(r => `
      <div class="severity-row">
        <span class="s-label">${r.label}</span>
        <span class="s-count">${r.count}</span>
      </div>`).join('');
  }

  const attempts = document.getElementById('attemptList');
  if (attempts) {
    const items = data.pending_attempts || [];
    attempts.innerHTML = items.length
      ? items.slice().reverse().map(x => `
          <div class="list-item">
            <b>${x.device}</b>
            <div class="meta">File: ${x.file}</div>
            <div class="meta">${x.time} &bull; ${x.status}</div>
          </div>`).join('')
      : '<div class="list-item"><b style="color:var(--text-secondary)">No decryption attempts yet.</b></div>';
  }
}

async function refreshDevices() {
  const data = await fetchJSON('/devices');

  const authList = document.getElementById('authorizedList');
  if (authList) {
    authList.innerHTML = (data.authorized || []).length
      ? data.authorized.map(d => `
          <div class="list-item">
            <b>${d.device}</b>
            <div class="meta">IP: ${d.ip} &bull; Owner: ${d.owner || 'n/a'}</div>
            <div class="row-actions">
              <button onclick="blockDevice('${d.device}')">Block</button>
              <button onclick="revokeDevice('${d.device}')">Revoke</button>
            </div>
          </div>`).join('')
      : '<div class="list-item"><b style="color:var(--text-secondary)">No authorized devices.</b></div>';
  }

  const blockedList = document.getElementById('blockedList');
  if (blockedList) {
    blockedList.innerHTML = (data.blocked || []).length
      ? data.blocked.map(d => `
          <div class="list-item">
            <b>${d}</b>
            <div class="row-actions">
              <button onclick="unblockDevice('${d}')">Unblock</button>
            </div>
          </div>`).join('')
      : '<div class="list-item"><b style="color:var(--text-secondary)">No blocked devices.</b></div>';
  }
}

async function authorizeDevice() {
  const device = document.getElementById('authDevice').value.trim();
  const ip     = document.getElementById('authIp').value.trim() || '*';
  const owner  = document.getElementById('authOwner').value.trim() || 'Server Manager';
  if (!device) return alert('Device name required');
  await fetchJSON('/authorize-device', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device, ip, owner })
  });
  document.getElementById('authDevice').value = '';
  document.getElementById('authIp').value = '';
  document.getElementById('authOwner').value = '';
  refreshAll();
}

async function revokeDevice(device) {
  await fetchJSON('/revoke-device', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ device }) });
  refreshAll();
}
async function blockDevice(device) {
  await fetchJSON('/block-device', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ device }) });
  refreshAll();
}
async function unblockDevice(device) {
  await fetchJSON('/unblock-device', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ device }) });
  refreshAll();
}
async function clearLogs() {
  await fetchJSON('/clear', { method: 'POST' });
  location.reload();
}

function exportCSV() {
  const rows = [...document.querySelectorAll('#logBody tr')]
    .filter(tr => tr.style.display !== 'none');
  if (!rows.length) return alert('No events to export.');
  const header = ['Timestamp', 'Device', 'IP', 'File', 'Action', 'Severity', 'Hash'];
  const lines = [header.join(',')];
  rows.forEach(tr => {
    const cells = [...tr.querySelectorAll('td')].map(td => `"${td.textContent.replace(/"/g, '""')}"`);
    lines.push(cells.join(','));
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `nexus_events_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
}

function prependLog(block) {
  if (!block.data) return;
  const tbody = document.getElementById('logBody');
  if (!tbody) return;
  const sev = block.data.severity || 'NORMAL';
  const tr = document.createElement('tr');
  tr.dataset.severity = sev;
  tr.innerHTML = `
    <td class="mono">${block.timestamp}</td>
    <td><b>${block.data.device}</b></td>
    <td class="mono">${block.data.ip}</td>
    <td class="mono">${block.data.file}</td>
    <td>${block.data.action}</td>
    <td><span class="badge badge-${sev}">${sev}</span></td>
    <td class="mono" title="${block.hash || ''}">${(block.hash || '').slice(0,12)}…</td>`;
  tbody.prepend(tr);
}

function connectSSE() {
  const evt = new EventSource('/stream');
  const dot  = document.getElementById('liveDot');
  const text = document.getElementById('liveText');

  evt.onopen = () => {
    if (dot)  { dot.className  = 'pulse-dot'; }
    if (text) { text.textContent = 'LIVE'; }
  };
  evt.onmessage = e => {
    if (!e.data) return;
    const data = JSON.parse(e.data);
    if (data.type === 'clear') { location.reload(); return; }
    prependLog(data);
    refreshAll();
  };
  evt.onerror = () => {
    if (dot)  { dot.className  = 'pulse-dot disconnected'; }
    if (text) { text.textContent = 'Reconnecting...'; }
    evt.close();
    setTimeout(connectSSE, 3000);
  };
}

async function refreshAll() {
  await Promise.all([updateStats(), refreshDevices()]);
}

refreshAll();
connectSSE();

// --- Theme Toggle ---
function toggleTheme() {
  const body = document.body;
  const icon = document.getElementById("themeIcon");
  body.classList.toggle("light-mode");
  
  if (body.classList.contains("light-mode")) {
    localStorage.setItem("nexus-theme", "light");
    icon.innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
  } else {
    localStorage.setItem("nexus-theme", "dark");
    icon.innerHTML = '<circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>';
  }
}

// Restore theme on load
document.addEventListener("DOMContentLoaded", () => {
  const saved = localStorage.getItem("nexus-theme");
  if (saved === "light") {
    document.body.classList.add("light-mode");
    document.getElementById("themeIcon").innerHTML = '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>';
  }
});
