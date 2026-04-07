import { Router } from "express";
import { requireRole } from "../middleware/auth.js";

const setupRouter = Router();

setupRouter.get("/", requireRole("super_admin", "admin"), (_req, res) => {
  const role = _req.user!.role;
  const isSuperAdmin = role === "super_admin";

  res.setHeader("Content-Type", "text/html");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Gateway — Setup</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');
  :root {
    --bg: #0a0a0b; --bg2: #111113; --bg3: #161618; --bg4: #1c1c1f;
    --text: #f0ede8; --text2: #9a978f; --text3: #5c5a54;
    --accent: #e8872a; --accent2: #f5c842; --accent3: #d4512a;
    --green: #34d399; --red: #f87171; --border: rgba(240,237,232,0.08);
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Outfit', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 32px 24px; }
  h1 { font-size: 1.8rem; margin-bottom: 8px; }
  h2 { font-size: 1.3rem; margin: 32px 0 16px; color: var(--accent); }
  h3 { font-size: 1.1rem; margin: 16px 0 8px; }
  .subtitle { color: var(--text2); margin-bottom: 32px; }
  .card { background: var(--bg3); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 16px; }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .card-header h3 { margin: 0; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 100px; font-size: 0.75rem; font-weight: 600; }
  .badge-green { background: rgba(52,211,153,0.15); color: var(--green); }
  .badge-red { background: rgba(248,113,113,0.15); color: var(--red); }
  .badge-orange { background: rgba(232,135,42,0.15); color: var(--accent); }
  .badge-gray { background: rgba(154,151,143,0.15); color: var(--text2); }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--text2); font-weight: 500; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
  td { font-size: 0.95rem; }
  button, .btn { padding: 8px 20px; border: none; border-radius: 6px; cursor: pointer; font-family: inherit; font-weight: 600; font-size: 0.85rem; transition: opacity 0.2s; }
  button:hover, .btn:hover { opacity: 0.85; }
  .btn-primary { background: linear-gradient(135deg, var(--accent2), var(--accent), var(--accent3)); color: #0a0a0b; }
  .btn-sm { padding: 5px 14px; font-size: 0.8rem; }
  .btn-danger { background: var(--red); color: white; }
  .btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text2); }
  input, select { padding: 8px 14px; background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-family: inherit; font-size: 0.9rem; width: 100%; }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
  .form-row.full { grid-template-columns: 1fr; }
  label { font-size: 0.85rem; color: var(--text2); margin-bottom: 4px; display: block; }
  .actions { display: flex; gap: 8px; align-items: center; }
  .toggle { position: relative; width: 44px; height: 24px; cursor: pointer; }
  .toggle input { opacity: 0; width: 0; height: 0; }
  .toggle .slider { position: absolute; inset: 0; background: var(--bg2); border-radius: 24px; border: 1px solid var(--border); transition: 0.2s; }
  .toggle .slider:before { content: ''; position: absolute; width: 18px; height: 18px; left: 2px; top: 2px; background: var(--text3); border-radius: 50%; transition: 0.2s; }
  .toggle input:checked + .slider { background: var(--accent); border-color: var(--accent); }
  .toggle input:checked + .slider:before { transform: translateX(20px); background: white; }
  .nav { display: flex; gap: 24px; border-bottom: 1px solid var(--border); margin-bottom: 32px; }
  .nav a { color: var(--text2); text-decoration: none; padding: 12px 0; font-weight: 500; border-bottom: 2px solid transparent; }
  .nav a.active { color: var(--accent); border-bottom-color: var(--accent); }
  .nav a:hover { color: var(--text); }
  .empty { text-align: center; padding: 40px; color: var(--text3); }
  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100; justify-content: center; align-items: center; }
  .modal-overlay.active { display: flex; }
  .modal { background: var(--bg3); border: 1px solid var(--border); border-radius: 12px; padding: 28px; width: 90%; max-width: 500px; }
  .modal h3 { margin-bottom: 16px; }
  .modal .form-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 20px; }
  .user-email { font-size: 0.85rem; color: var(--text2); }
  #toast { position: fixed; bottom: 24px; right: 24px; padding: 12px 24px; background: var(--green); color: #0a0a0b; border-radius: 8px; font-weight: 600; display: none; z-index: 200; }
</style>
</head>
<body>
<div class="container">
  <h1>MCP Gateway</h1>
  <p class="subtitle">Manage clients, services, and access — <strong>${_req.user!.email}</strong> (${role})</p>

  <div class="nav">
    <a href="#" class="active" onclick="showTab('clients')">Clients & MCPs</a>
    ${isSuperAdmin ? '<a href="#" onclick="showTab(\'users\')">Users & Roles</a>' : ''}
    ${isSuperAdmin ? '<a href="#" onclick="showTab(\'access\')">Access Control</a>' : ''}
  </div>

  <!-- Clients Tab -->
  <div id="tab-clients">
    <div style="display:flex;gap:12px;margin-bottom:16px">
    ${isSuperAdmin ? '<button class="btn btn-primary" onclick="showAddClient()">+ Add Client</button>' : ''}
    <button class="btn btn-ghost" onclick="syncProjects()">🔄 Sync from Zoho Projects</button>
    </div>
    <div id="clients-list"></div>
  </div>

  <!-- Users Tab -->
  <div id="tab-users" style="display:none">
    <div id="users-list"></div>
  </div>

  <!-- Access Tab -->
  <div id="tab-access" style="display:none">
    <p style="color:var(--text2);margin-bottom:16px">Select a user to manage their per-service access overrides.</p>
    <select id="access-user-select" onchange="loadUserAccess()" style="max-width:400px;margin-bottom:24px">
      <option value="">Select a user...</option>
    </select>
    <div id="access-grid"></div>
  </div>
</div>

<!-- Add Client Modal -->
<div class="modal-overlay" id="modal-client">
  <div class="modal">
    <h3 id="client-modal-title">Add Client</h3>
    <input type="hidden" id="client-edit-id">
    <div class="form-row">
      <div><label>Zoho Project ID</label><input id="client-project-id" placeholder="2492385000000487005"></div>
      <div><label>Display Name</label><input id="client-name" placeholder="Melody Lane Home Pros"></div>
    </div>
    <div class="form-row full">
      <div><label>Prefix (lowercase, no spaces)</label><input id="client-prefix" placeholder="melodylane"></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-client')">Cancel</button>
      <button class="btn btn-primary" onclick="saveClient()">Save</button>
    </div>
  </div>
</div>

<!-- Add Service Modal -->
<div class="modal-overlay" id="modal-service">
  <div class="modal">
    <h3 id="service-modal-title">Add MCP Service</h3>
    <input type="hidden" id="service-edit-id">
    <input type="hidden" id="service-client-id">
    <div class="form-row">
      <div><label>Service Name</label><input id="service-name" placeholder="ghost"></div>
      <div><label>Backend URL</label><input id="service-url" placeholder="http://127.0.0.1:3100"></div>
    </div>
    <div class="form-row">
      <div><label>API Key Env Var</label><input id="service-apikey" placeholder="GHOST_MCP_API_KEY"></div>
      <div><label>Auth Type</label>
        <select id="service-authtype">
          <option value="api_key">API Key</option>
          <option value="oauth">OAuth</option>
          <option value="none">None</option>
        </select>
      </div>
    </div>
    <div class="form-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-service')">Cancel</button>
      <button class="btn btn-primary" onclick="saveService()">Save</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
const API = '/setup/api';
const IS_SUPER = ${isSuperAdmin};

async function api(path, method = 'GET', body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'include' };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(API + path, opts);
  if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || res.statusText); }
  return res.json();
}

function toast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 2500);
}

function showTab(name) {
  document.querySelectorAll('[id^="tab-"]').forEach(el => el.style.display = 'none');
  document.getElementById('tab-' + name).style.display = 'block';
  document.querySelectorAll('.nav a').forEach(a => a.classList.remove('active'));
  event.target.classList.add('active');
  if (name === 'clients') loadClients();
  if (name === 'users') loadUsers();
  if (name === 'access') loadAccessTab();
}

function closeModal(id) { document.getElementById(id).classList.remove('active'); }
function openModal(id) { document.getElementById(id).classList.add('active'); }

// ── Clients ──
async function loadClients() {
  const clients = await api('/clients');
  const el = document.getElementById('clients-list');
  if (!clients.length) { el.innerHTML = '<div class="empty">No clients configured yet. Add one to get started.</div>'; return; }

  let html = '';
  for (const c of clients) {
    const services = await api('/clients/' + c.project_id + '/services');
    html += '<div class="card"><div class="card-header"><div><h3>' + c.name + '</h3><span class="user-email">Prefix: ' + c.prefix + ' &middot; Project: ' + c.project_id + '</span></div><div class="actions">';
    if (IS_SUPER) html += '<button class="btn btn-sm btn-ghost" onclick="showAddService(\\'' + c.project_id + '\\')">+ Add MCP</button>';
    if (IS_SUPER) html += '<button class="btn btn-sm btn-danger" onclick="deleteClient(\\'' + c.project_id + '\\')">Delete</button>';
    html += '</div></div>';

    if (services.length) {
      html += '<table><thead><tr><th>Service</th><th>URL</th><th>Auth</th><th>Status</th><th></th></tr></thead><tbody>';
      for (const s of services) {
        html += '<tr><td><strong>' + s.name + '</strong></td><td style="color:var(--text2);font-size:0.85rem">' + s.url + '</td>';
        html += '<td><span class="badge badge-gray">' + s.auth_type + '</span></td>';
        html += '<td>' + (s.enabled ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Disabled</span>') + '</td>';
        html += '<td class="actions">';
        html += '<label class="toggle"><input type="checkbox" ' + (s.enabled ? 'checked' : '') + ' onchange="toggleService(' + s.id + ', this.checked)"><span class="slider"></span></label>';
        html += ' <button class="btn btn-sm btn-ghost" onclick="editService(' + s.id + ',\\'' + s.client_project_id + '\\',\\'' + s.name + '\\',\\'' + s.url + '\\',\\'' + (s.api_key_env||'') + '\\',\\'' + s.auth_type + '\\')">Edit</button>';
        if (IS_SUPER) html += ' <button class="btn btn-sm btn-danger" onclick="deleteService(' + s.id + ')">×</button>';
        html += '</td></tr>';
      }
      html += '</tbody></table>';
    } else {
      html += '<div class="empty" style="padding:20px">No MCPs configured for this client yet.</div>';
    }
    html += '</div>';
  }
  el.innerHTML = html;
}

function showAddClient() {
  document.getElementById('client-modal-title').textContent = 'Add Client';
  document.getElementById('client-project-id').value = '';
  document.getElementById('client-name').value = '';
  document.getElementById('client-prefix').value = '';
  document.getElementById('client-project-id').disabled = false;
  openModal('modal-client');
}

async function saveClient() {
  try {
    await api('/clients', 'POST', {
      project_id: document.getElementById('client-project-id').value,
      name: document.getElementById('client-name').value,
      prefix: document.getElementById('client-prefix').value,
    });
    closeModal('modal-client'); toast('Client saved'); loadClients();
  } catch (e) { alert(e.message); }
}

async function deleteClient(id) {
  if (!confirm('Delete this client and all its services?')) return;
  await api('/clients/' + id, 'DELETE');
  toast('Client deleted'); loadClients();
}

// ── Services ──
function showAddService(clientId) {
  document.getElementById('service-modal-title').textContent = 'Add MCP Service';
  document.getElementById('service-edit-id').value = '';
  document.getElementById('service-client-id').value = clientId;
  document.getElementById('service-name').value = '';
  document.getElementById('service-url').value = '';
  document.getElementById('service-apikey').value = '';
  document.getElementById('service-authtype').value = 'api_key';
  openModal('modal-service');
}

function editService(id, clientId, name, url, apiKey, authType) {
  document.getElementById('service-modal-title').textContent = 'Edit MCP Service';
  document.getElementById('service-edit-id').value = id;
  document.getElementById('service-client-id').value = clientId;
  document.getElementById('service-name').value = name;
  document.getElementById('service-url').value = url;
  document.getElementById('service-apikey').value = apiKey;
  document.getElementById('service-authtype').value = authType;
  openModal('modal-service');
}

async function saveService() {
  const editId = document.getElementById('service-edit-id').value;
  const data = {
    name: document.getElementById('service-name').value,
    url: document.getElementById('service-url').value,
    api_key_env: document.getElementById('service-apikey').value,
    auth_type: document.getElementById('service-authtype').value,
  };
  try {
    if (editId) {
      await api('/services/' + editId, 'PUT', data);
    } else {
      const clientId = document.getElementById('service-client-id').value;
      await api('/clients/' + clientId + '/services', 'POST', data);
    }
    closeModal('modal-service'); toast('Service saved'); loadClients();
  } catch (e) { alert(e.message); }
}

async function toggleService(id, enabled) {
  await api('/services/' + id, 'PUT', { enabled: enabled ? 1 : 0 });
  toast(enabled ? 'Service enabled' : 'Service disabled');
}

async function deleteService(id) {
  if (!confirm('Delete this service?')) return;
  await api('/services/' + id, 'DELETE');
  toast('Service deleted'); loadClients();
}

// ── Users ──
async function loadUsers() {
  const users = await api('/users');
  const el = document.getElementById('users-list');
  let html = '<table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th></th></tr></thead><tbody>';
  for (const u of users) {
    const roleBadge = u.role === 'super_admin' ? 'badge-orange' : u.role === 'admin' ? 'badge-green' : 'badge-gray';
    html += '<tr><td><strong>' + u.name + '</strong></td><td style="color:var(--text2)">' + u.email + '</td>';
    html += '<td><select onchange="changeRole(\\'' + u.zuid + '\\', this.value)" style="width:auto;padding:4px 8px">';
    for (const r of ['super_admin', 'admin', 'dev']) {
      html += '<option value="' + r + '" ' + (u.role === r ? 'selected' : '') + '>' + r.replace('_', ' ') + '</option>';
    }
    html += '</select></td>';
    html += '<td><button class="btn btn-sm btn-danger" onclick="deleteUser(\\'' + u.zuid + '\\')">Remove</button></td></tr>';
  }
  html += '</tbody></table>';
  html += '<p style="color:var(--text3);margin-top:16px;font-size:0.85rem">New users are auto-added as "dev" when they first authenticate via Zoho SSO.</p>';
  el.innerHTML = html;
}

async function changeRole(zuid, role) {
  await api('/users/' + zuid + '/role', 'PUT', { role });
  toast('Role updated');
}

async function deleteUser(zuid) {
  if (!confirm('Remove this user?')) return;
  await api('/users/' + zuid, 'DELETE');
  toast('User removed'); loadUsers();
}

// ── Access Control ──
async function loadAccessTab() {
  const users = await api('/users');
  const sel = document.getElementById('access-user-select');
  sel.innerHTML = '<option value="">Select a user...</option>';
  for (const u of users) {
    sel.innerHTML += '<option value="' + u.zuid + '">' + u.name + ' (' + u.email + ') — ' + u.role + '</option>';
  }
}

async function loadUserAccess() {
  const zuid = document.getElementById('access-user-select').value;
  const el = document.getElementById('access-grid');
  if (!zuid) { el.innerHTML = ''; return; }

  const [clients, overrides] = await Promise.all([api('/clients'), api('/users/' + zuid + '/access')]);
  const overrideMap = {};
  for (const o of overrides) overrideMap[o.service_id] = o.enabled;

  let html = '';
  for (const c of clients) {
    const services = await api('/clients/' + c.project_id + '/services');
    if (!services.length) continue;

    html += '<div class="card"><h3>' + c.name + '</h3><table><thead><tr><th>Service</th><th>Default</th><th>Override</th></tr></thead><tbody>';
    for (const s of services) {
      const hasOverride = overrideMap[s.id] !== undefined;
      const isEnabled = hasOverride ? overrideMap[s.id] === 1 : true;
      html += '<tr><td><strong>' + s.name + '</strong></td>';
      html += '<td><span class="badge badge-green">Enabled (project member)</span></td>';
      html += '<td><select onchange="setAccess(\\'' + zuid + '\\', ' + s.id + ', this.value)" style="width:auto;padding:4px 8px">';
      html += '<option value="default" ' + (!hasOverride ? 'selected' : '') + '>Default (enabled)</option>';
      html += '<option value="1" ' + (hasOverride && isEnabled ? 'selected' : '') + '>Force Enable</option>';
      html += '<option value="0" ' + (hasOverride && !isEnabled ? 'selected' : '') + '>Force Disable</option>';
      html += '</select></td></tr>';
    }
    html += '</tbody></table></div>';
  }
  el.innerHTML = html || '<div class="empty">No services configured yet.</div>';
}

async function setAccess(zuid, serviceId, value) {
  if (value === 'default') {
    await api('/users/' + zuid + '/access/' + serviceId, 'DELETE');
  } else {
    await api('/users/' + zuid + '/access/' + serviceId, 'PUT', { enabled: value === '1' });
  }
  toast('Access updated');
}

// ── Sync Projects ──
async function syncProjects() {
  try {
    const result = await api('/sync-projects', 'POST');
    if (result.newly_added > 0) {
      toast('Synced! Added ' + result.newly_added + ' new client(s): ' + result.added_clients.join(', '));
    } else {
      toast('All ' + result.total_projects + ' projects already synced');
    }
    loadClients();
  } catch (e) { alert('Sync failed: ' + e.message); }
}

// Initial load
loadClients();
</script>
</body>
</html>`);
});

export default setupRouter;
