(function () {
  const output = document.getElementById('output');
  const statusEmbed = document.getElementById('status-embed');
  const addBotInput = document.getElementById('add-bot-name');
  const removeBotInput = document.getElementById('remove-bot-name');
  const botNamesList = document.getElementById('bot-names');
  const apiBaseInput = document.getElementById('api-base');
  const authGate = document.getElementById('auth-gate');
  const appMain = document.getElementById('app-main');
  const authOutput = document.getElementById('auth-output');
  const loginName = document.getElementById('login-name');
  const loginKey = document.getElementById('login-key');
  const btnLogin = document.getElementById('btn-login');
  const btnRequestAccess = document.getElementById('btn-request-access');
  const btnContinue = document.getElementById('btn-continue');
  const reqForm = document.getElementById('request-access-form');
  const reqContact = document.getElementById('req-contact');
  const reqNote = document.getElementById('req-note');
  const btnSubmitRequest = document.getElementById('btn-submit-request');

  // Default API base to current origin; allow override
  const defaultApiBase = window.location.origin;
  apiBaseInput.value = defaultApiBase;
  function getApiBase() {
    const base = apiBaseInput.value.trim() || defaultApiBase;
    try { return new URL(base).toString().replace(/\/$/, ''); } catch { return defaultApiBase; }
  }

  function log(result) {
    try {
      const text = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
      output.textContent = text;
    } catch (e) {
      output.textContent = String(result);
    }
  }

  async function callGet(path, params) {
    const url = new URL(path, getApiBase());
    Object.entries(params || {}).forEach(([k, v]) => {
      if (v !== undefined && v !== null && String(v).length > 0) url.searchParams.set(k, v);
    });
    const res = await fetch(url.toString(), { method: 'GET' });
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) return res.json();
    return res.text();
  }

  async function callPost(path, body) {
    const res = await fetch(new URL(path, getApiBase()).toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {})
    });
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      const data = await res.json();
      if (!res.ok) throw new Error(data?.message || 'Request failed');
      return data;
    }
    if (!res.ok) throw new Error('Request failed with status ' + res.status);
    return null;
  }

  async function loadAccounts() {
    try {
      const data = await callGet('/accounts');
      const accounts = Array.isArray(data?.accounts) ? data.accounts : [];
      const toOption = (acc) => `<option value="${acc.name}" label="${acc.name} (${acc.uid})"></option>`;
      const html = accounts.map(toOption).join('');
      botNamesList.innerHTML = html;
    } catch (e) {
      log('Failed to load accounts. Add an account first.');
    }
  }

  // Add Friend
  document.getElementById('btn-add-friend').addEventListener('click', async () => {
    const botName = addBotInput.value.trim();
    const uid = document.getElementById('add-uid').value.trim();
    if (!botName || !uid) return log('Please provide both bot name and target UID.');
    try {
      const data = await callGet('/send_requests', { bot_name: botName, uid });
      log(data);
    } catch (e) {
      log(`Error: ${e.message || e}`);
    }
  });

  // Remove Friend
  document.getElementById('btn-remove-friend').addEventListener('click', async () => {
    const botName = removeBotInput.value.trim();
    const uid = document.getElementById('remove-uid').value.trim();
    if (!botName || !uid) return log('Please provide both bot name and target UID.');
    try {
      const data = await callGet('/remove_friend', { bot_name: botName, uid });
      log(data);
    } catch (e) {
      log(`Error: ${e.message || e}`);
    }
  });

  // Account Add
  document.getElementById('btn-acc-add').addEventListener('click', async () => {
    const name = document.getElementById('acc-add-name').value.trim();
    const uid = document.getElementById('acc-add-uid').value.trim();
    const password = document.getElementById('acc-add-pass').value.trim();
    if (!name || !uid || !password) return log('Please fill name, uid and password.');
    try {
      const data = await callGet('/add_account', { name, uid, password });
      log(data);
    } catch (e) {
      log(`Error: ${e.message || e}`);
    }
  });

  // Account Remove
  document.getElementById('btn-acc-remove').addEventListener('click', async () => {
    const name = document.getElementById('acc-remove-name').value.trim();
    if (!name) return log('Please provide account name to remove.');
    try {
      const data = await callGet('/remove_account', { name });
      log(data);
    } catch (e) {
      log(`Error: ${e.message || e}`);
    }
  });

  // Account Update
  document.getElementById('btn-acc-update').addEventListener('click', async () => {
    const name = document.getElementById('acc-update-name').value.trim();
    const uid = document.getElementById('acc-update-uid').value.trim();
    const password = document.getElementById('acc-update-pass').value.trim();
    if (!name) return log('Please provide account name to update.');
    try {
      const params = { name };
      if (uid) params.uid = uid;
      if (password) params.password = password;
      const data = await callGet('/update_account', params);
      log(data);
    } catch (e) {
      log(`Error: ${e.message || e}`);
    }
  });

  // Status embed
  document.getElementById('btn-status-embed').addEventListener('click', async () => {
    try {
      const data = await callGet('/status_json');
      // Build themed HTML
      const totals = data?.totals || { total: 0, online: 0, idle: 0, offline: 0 };
      const accounts = Array.isArray(data?.accounts) ? data.accounts : [];
      const chips = `
        <div class="status-summary">
          <div class="status-chip">Total: ${totals.total}</div>
          <div class="status-chip">Online: ${totals.online}</div>
          <div class="status-chip">Idle: ${totals.idle}</div>
          <div class="status-chip">Offline: ${totals.offline}</div>
          <div class="status-chip">Updated: ${data?.last_updated || ''}</div>
        </div>
      `;
      const items = accounts.map(acc => {
        const raw = (acc.status_raw || '').toLowerCase();
        const badgeClass = raw === 'online' ? 'online' : raw === 'idle' ? 'idle' : 'offline';
        return `
          <div class="status-item">
            <div class="name">${acc.name} <span class="meta">(${acc.uid})</span></div>
            <div class="status-badge ${badgeClass}">${acc.status}</div>
            <div class="meta">Last seen: ${acc.last_seen}</div>
          </div>
        `;
      }).join('');
      statusEmbed.innerHTML = chips + `<div class="status-list">${items}</div>`;
      statusEmbed.classList.remove('hidden');
    } catch (e) {
      log(`Error loading status: ${e.message || e}`);
    }
  });

  // Init
  (async function init() {
    try {
      // Connectivity check
      const res = await fetch(new URL('/status', getApiBase()).toString(), { method: 'GET' });
      if (!res.ok) throw new Error('Backend responded with status ' + res.status);
      // Auth check
      const me = await callGet('/auth/me');
      const authorized = !!(me && me.user);
      // Always show auth gate as requested. If authorized, show Continue button.
      authGate.classList.remove('hidden');
      btnContinue.classList.toggle('hidden', !authorized);
      appMain.classList.add('hidden');
    } catch (e) {
      const origin = window.location.origin;
      const hint = origin.startsWith('file:')
        ? 'Open the UI at http://127.0.0.1:5000/ui/ instead of opening the file directly.'
        : 'Ensure the Flask app is running and accessible at ' + origin + ' (default http://127.0.0.1:5000).';
      log('Cannot reach backend. ' + hint + '\n\nDetails: ' + (e.message || e));
    }
  })();

  // Auth events
  btnLogin.addEventListener('click', async () => {
    try {
      btnLogin.disabled = true;
      const data = await callPost('/auth/login', {
        name: loginName.value.trim(),
        access_key: loginKey.value.trim(),
      });
      authOutput.textContent = 'Logged in as ' + (data?.name || 'user') + '. Reloading...';
      setTimeout(() => window.location.reload(), 500);
    } catch (e) {
      authOutput.textContent = 'Login failed: ' + (e.message || e);
    } finally {
      btnLogin.disabled = false;
    }
  });

  btnRequestAccess.addEventListener('click', () => {
    reqForm.classList.toggle('hidden');
  });

  btnSubmitRequest.addEventListener('click', async () => {
    try {
      btnSubmitRequest.disabled = true;
      await callPost('/auth/request_access', {
        name: loginName.value.trim(),
        contact: reqContact.value.trim(),
        note: reqNote.value.trim(),
      });
      authOutput.textContent = 'Request submitted. The admin will contact you.';
    } catch (e) {
      authOutput.textContent = 'Failed to submit request: ' + (e.message || e);
    } finally {
      btnSubmitRequest.disabled = false;
    }
  });

  btnContinue.addEventListener('click', async () => {
    try {
      const name = loginName.value.trim();
      const access_key = loginKey.value.trim();
      if (!name || !access_key) {
        authOutput.textContent = 'Please enter Name and Access Key to continue.';
        return;
      }
      btnContinue.disabled = true;
      await callPost('/auth/login', { name, access_key });
      appMain.classList.remove('hidden');
      loadAccounts();
    } catch (e) {
      authOutput.textContent = 'Cannot continue: ' + (e.message || e);
    } finally {
      btnContinue.disabled = false;
    }
  });
})();


