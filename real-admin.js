(function(){
  'use strict';
  const $ = id => document.getElementById(id);
  const state = { security: {}, health: null, setupToken: null };

  async function api(url, options = {}) {
    const opts = { credentials: 'same-origin', ...options };
    opts.headers = { ...(options.headers || {}) };
    if (options.body && typeof options.body !== 'string') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(options.body);
    }
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.status = res.status; err.data = data;
      throw err;
    }
    return data;
  }

  function show(msg, type='info') {
    if (typeof showAlert === 'function') showAlert(msg, type);
    else console.log(`[${type}] ${msg}`);
  }

  function confirmDanger(title, text) {
    if (typeof dangerConfirm === 'function') {
      return new Promise(resolve => dangerConfirm(title, text, () => resolve(true)));
    }
    return Promise.resolve(window.confirm(`${title}\n\n${text}`));
  }

  function promptText(title, placeholder='') {
    if (window.Swal) {
      return Swal.fire({ title, input:'text', inputPlaceholder:placeholder, showCancelButton:true, confirmButtonText:'Continue' }).then(r => r.isConfirmed ? r.value : null);
    }
    return Promise.resolve(window.prompt(title, placeholder));
  }

  function renderHealth(snapshot) {
    state.health = snapshot;
    const map = { firebase:'firebaseStatus', mongodb:'mongoStatus', mysql:'mysqlStatus', redis:'redisStatus' };
    for (const [name, id] of Object.entries(map)) {
      const el = $(id); const item = snapshot.services?.[name];
      if (!el || !item) continue;
      el.textContent = item.status === 'CONNECTED' ? `Connected (${item.latency_ms}ms)` : `${item.status}${item.error ? ` — ${item.error.message || item.error}` : ''}`;
      const parent = el.closest('.database-card');
      if (parent) {
        parent.dataset.healthStatus = item.status;
        parent.style.borderColor = item.status === 'CONNECTED' ? 'rgba(52,211,153,.25)' : 'rgba(248,113,113,.3)';
      }
    }
    const online = ['firebase','mongodb','mysql','redis'].filter(k => snapshot.services?.[k]?.status === 'CONNECTED').length;
    const summary = $('dbHealthSummary');
    if (summary) summary.textContent = `${online}/4 connected • ${new Date(snapshot.checked_at).toLocaleTimeString()}`;
  }

  async function loadDatabaseStatsReal() {
    try {
      const snapshot = await api('/api/health');
      renderHealth(snapshot);
    } catch (err) {
      if (err.data?.services) renderHealth(err.data);
      else show(`❌ DB health check failed: ${err.data?.error || err.message}`, 'error');
    }
  }

  async function databaseAction(db, confirmation) {
    const ok = await promptText(`Type exactly: ${confirmation}`, confirmation);
    if (ok !== confirmation) { show('❌ Confirmation mismatch.', 'error'); return; }
    try {
      const result = await api(`/api/admin/databases/${encodeURIComponent(db)}/clear`, { method:'POST', body:{confirm:confirmation} });
      show(`✅ ${db} cleared: ${result.status}`, 'success');
      await loadDatabaseStatsReal();
    } catch (err) {
      show(`❌ ${db} clear failed: ${err.data?.error || err.message}`, 'error');
    }
  }

  window.ScannerAPIReal = window.ScannerAPIReal || {};
  window.ScannerAPIReal.loadDatabaseStats = loadDatabaseStatsReal;
  window.ScannerAPIReal.loadSecuritySettings = loadSecurityReal;
  window.loadDatabaseStats = loadDatabaseStatsReal;
  window.checkMongoDBStatus = loadDatabaseStatsReal;
  window.checkMySQLStatus = loadDatabaseStatsReal;
  window.checkRedisStatus = loadDatabaseStatsReal;
  window.ScannerAPIReal.syncMongoDB = loadDatabaseStatsReal;
  window.ScannerAPIReal.syncMySQL = loadDatabaseStatsReal;
  window.ScannerAPIReal.clearMongoDB = () => databaseAction('mongodb', 'DELETE ALL MONGODB DATA');
  window.ScannerAPIReal.clearMySQL = () => databaseAction('mysql', 'DELETE ALL MYSQL DATA');
  window.ScannerAPIReal.clearRedis = () => databaseAction('redis', 'DELETE ALL REDIS DATA');
  window.clearMySQL = window.ScannerAPIReal.clearMySQL;
  window.clearRedis = window.ScannerAPIReal.clearRedis;
  window.refreshRedis = loadDatabaseStatsReal;

  // Replace the old “delete all” behavior with the server-side authenticated endpoint.
  window.deleteAllDatabaseData = async function(){
    const ok = await promptText('Type exactly: DELETE ALL DATABASE DATA', 'DELETE ALL DATABASE DATA');
    if (ok !== 'DELETE ALL DATABASE DATA') { show('❌ Confirmation mismatch.', 'error'); return; }
    try {
      const result = await api('/api/admin/databases/delete-all', { method:'POST', body:{confirm:'DELETE ALL DATABASE DATA'} });
      show(result.ok ? '✅ All configured databases were cleared.' : '⚠️ Some databases could not be cleared.', result.ok ? 'success' : 'warning');
      if (result.ok) location.href='/login.html';
      else await loadDatabaseStatsReal();
    } catch (err) {
      show(`❌ Delete-all failed: ${err.data?.error || err.message}`, 'error');
    }
  };

  async function loadSecurityReal(){
    try {
      const me = await api('/api/admin/me');
      state.security = me.security || {};
      const ip = $('currentIPDisplay'); if (ip) ip.value = me.ip || '';
      const toggle = $('ipToggle'); const text = $('ipStatusText');
      if (toggle) toggle.classList.toggle('active', Boolean(state.security.ip_verification_enabled));
      if (text) text.textContent = state.security.ip_verification_enabled ? 'Enabled' : 'Disabled';
      const allowed = $('allowedIPsInput'); if (allowed) allowed.value = state.security.allowed_ips || '';
      const two = $('twoFAStatus'); if (two) { two.textContent = state.security.two_fa_enabled ? '✅ Enabled' : '❌ Disabled'; two.className = 'badge ' + (state.security.two_fa_enabled ? 'badge-online' : 'badge-offline'); }
      const backup = $('backupCodesDisplay'); if (backup) backup.innerHTML = `<pre style="margin:0;color:#34d399;">${state.security.backup_codes_remaining || 0} unused backup codes remaining</pre>`;
    } catch (err) {
      if (err.status === 401 || err.status === 403) location.href='/login.html';
      else show(`❌ Security load failed: ${err.data?.error || err.message}`, 'error');
    }
  }
  window.loadSecuritySettings = loadSecurityReal;

  window.toggleIPVerification = async function(){
    const enabled = !$('ipToggle')?.classList.contains('active');
    if ($('ipToggle')) $('ipToggle').classList.toggle('active', enabled);
    if ($('ipStatusText')) $('ipStatusText').textContent = enabled ? 'Enabled' : 'Disabled';
    state.pendingIpEnabled = enabled;
  };

  window.saveIPSettings = async function(){
    const enabled = state.pendingIpEnabled ?? $('ipToggle')?.classList.contains('active');
    const allowed = $('allowedIPsInput')?.value.trim() || '';
    try { await api('/api/admin/ip-settings',{method:'POST',body:{enabled,allowed_ips:allowed}}); show('✅ IP settings saved on server.','success'); await loadSecurityReal(); }
    catch(err){ show(`❌ IP settings failed: ${err.data?.error || err.message}`,'error'); }
  };

  window.toggle2FA = async function(){
    try {
      if (state.security.two_fa_enabled) {
        const code = await promptText('Enter current 6-digit TOTP to disable 2FA');
        if (!code) return;
        await api('/api/admin/2fa/disable',{method:'POST',body:{code}});
        show('✅ Real TOTP 2FA disabled.','success');
        await loadSecurityReal();
        return;
      }
      const setup = await api('/api/admin/2fa/setup',{method:'POST'});
      state.setupToken = setup.setup_token;
      const result = await Swal.fire({
        title:'🔐 Enable real TOTP 2FA',
        html:`<p>Scan this QR code with Google Authenticator/Authy.</p><img src="${setup.qr_data_url}" class="qr" alt="TOTP QR"><p style="font-size:12px;word-break:break-all;">Secret: ${setup.secret}</p><input id="setupOtp" class="swal2-input" maxlength="6" inputmode="numeric" placeholder="6-digit code">`,
        showCancelButton:true,confirmButtonText:'Enable 2FA',preConfirm:()=>document.getElementById('setupOtp')?.value?.trim() || ''
      });
      if (!result.isConfirmed) return;
      const enabled = await api('/api/admin/2fa/enable',{method:'POST',body:{setup_token:state.setupToken,code:result.value}});
      await Swal.fire({title:'Backup codes',html:`<pre style="text-align:left;white-space:pre-wrap;">${enabled.backup_codes.join('\n')}</pre><p>These are shown once. Each is single-use.</p>`,confirmButtonText:'I saved them'});
      show('✅ Real TOTP 2FA enabled.','success');
      await loadSecurityReal();
    } catch(err){ show(`❌ 2FA setup failed: ${err.data?.error || err.message}`,'error'); }
  };

  window.generateBackupCodes = async function(){
    try {
      const code = await promptText('Enter current 6-digit TOTP to regenerate backup codes');
      if (!code) return;
      const result = await api('/api/admin/2fa/regenerate-backup',{method:'POST',body:{code}});
      await Swal.fire({title:'New backup codes',html:`<pre style="text-align:left;white-space:pre-wrap;">${result.backup_codes.join('\n')}</pre>`,confirmButtonText:'I saved them'});
      await loadSecurityReal();
    } catch(err){ show(`❌ Backup code regeneration failed: ${err.data?.error || err.message}`,'error'); }
  };

  window.verifyOTP = async function(){
    show('ℹ️ OTP verification happens during server-side login.','info');
  };

  window.terminateSession = async function(sessionId){
    if (sessionId !== 'current') return;
    try { await api('/api/admin/logout',{method:'POST'}); location.href='/login.html'; } catch(err){ show(`❌ Logout failed: ${err.data?.error || err.message}`,'error'); }
  };

  window.terminateAllSessions = async function(){
    const ok = await confirmDanger('Terminate all admin sessions?', 'Every existing admin session will be invalidated. You will be logged out too.');
    if (!ok) return;
    try { await api('/api/admin/sessions/terminate-all',{method:'POST'}); location.href='/login.html'; }
    catch(err){ show(`❌ Session termination failed: ${err.data?.error || err.message}`,'error'); }
  };

  window.ScannerAPIReal.handleLogout = async function(){};
  window.handleLogout = async function(){
    try { await api('/api/admin/logout',{method:'POST'}); } catch {}
    location.href='/login.html';
  };

  window.changeApiKeyWithVerification = async function(){
    const userId = $('changeApiKeyUser')?.value;
    const currentKey = $('verifyCurrentApiKey')?.value.trim();
    const newKey = $('newApiKeyInput')?.value.trim();
    if (!userId || !currentKey) return show('⚠️ Select a user and enter the current API key.','error');
    try {
      const data = await api('/api/admin/api-key/rotate',{method:'POST',body:{user_id:userId,current_key:currentKey,new_key:newKey}});
      if ($('currentApiKeyDisplay')) $('currentApiKeyDisplay').value = data.api_key;
      if ($('verifyCurrentApiKey')) $('verifyCurrentApiKey').value='';
      if ($('newApiKeyInput')) $('newApiKeyInput').value='';
      show('✅ API key rotated using server-side verification.','success');
    } catch(err) { show(`❌ API-key rotation failed: ${err.data?.error || err.message}`,'error'); }
  };

  window.addActivity = async function(message){
    try { await api('/api/admin/activity',{method:'POST',body:{message}}); } catch { /* server logs are best-effort */ }
  };
  window.ScannerAPIReal.addActivity = window.addActivity;

  // Endpoint for addActivity is intentionally tiny; create it on the server if not present in an older deployment.
  async function loadActivityReal(){
    try {
      const data = await api('/api/admin/activity');
      const feed = $('activityFeed');
      if (!feed) return;
      const items = data.activity || [];
      feed.innerHTML = items.length ? items.map(a=>`<div class="activity-item"><span>${escapeHtml(a.message || '')}</span><span class="time">${a.timestamp ? new Date(a.timestamp).toLocaleString() : ''}</span></div>`).join('') : '<div class="activity-item"><span>No activity yet</span><span class="time">-</span></div>';
    } catch(err){ show(`❌ Activity load failed: ${err.data?.error || err.message}`,'error'); }
  }
  window.loadActivityFeed = loadActivityReal;
  window.ScannerAPIReal.loadActivityFeed = loadActivityReal;

  window.clearLogs = async function(){ try { await api('/api/admin/clear-data',{method:'POST',body:{target:'logs'}}); show('✅ Firebase logs cleared.','success'); loadStats?.(); } catch(err){ show(`❌ ${err.message}`,'error'); } };
  window.clearAllLogs = window.clearLogs;
  window.ScannerAPIReal.clearLogs = window.clearLogs;
  window.clearFailedLogins = async function(){ try { await api('/api/admin/clear-data',{method:'POST',body:{target:'failed_logins'}}); show('✅ Failed-login log cleared.','success'); loadSecurityReal(); } catch(err){ show(`❌ ${err.message}`,'error'); } };

  window.ScannerAPIReal.clearFailedLogins = window.clearFailedLogins;

  window.resetAll = async function(){
    const ok = await confirmDanger('Reset logs/activity?', 'This clears activity, request logs and failed-login logs. User records are not deleted.');
    if (!ok) return;
    try { await api('/api/admin/clear-data',{method:'POST',body:{target:'activity-all'}}); show('✅ Activity/log data cleaned across configured stores.','success'); await loadActivityReal(); }
    catch(err){ show(`❌ Cleanup failed: ${err.data?.error || err.message}`,'error'); }
  };

  window.ScannerAPIReal.resetAll = window.resetAll;
  window.clearFirebase = () => databaseAction('firebase','DELETE ALL FIREBASE DATA');
  window.ScannerAPIReal.clearFirebase = window.clearFirebase;
  window.ScannerAPIReal.deleteAllDatabaseData = window.deleteAllDatabaseData;
  window.ScannerAPIReal.terminateAllSessions = window.terminateAllSessions;
  window.ScannerAPIReal.terminateSession = window.terminateSession;
  window.ScannerAPIReal.toggle2FA = window.toggle2FA;
  window.ScannerAPIReal.generateBackupCodes = window.generateBackupCodes;
  window.ScannerAPIReal.verifyOTP = window.verifyOTP;
  window.ScannerAPIReal.changeApiKeyWithVerification = window.changeApiKeyWithVerification;

  window.loadApiTestData = function(){};

  function addHealthSummaryUI(){
    if (!$('dbHealthSummary')) {
      const headings = document.querySelectorAll('#tabDatabases h3');
      const h = headings[0];
      if (h) { const s=document.createElement('span'); s.id='dbHealthSummary'; s.style='float:right;font-size:12px;color:#9ca3af'; s.textContent='Checking...'; h.appendChild(s); }
    }
    const activityTitle=document.querySelector('#tabActivity h3');
    if (activityTitle && !document.getElementById('clearActivityBtn')) {
      const b=document.createElement('button'); b.id='clearActivityBtn'; b.className='btn btn-danger btn-sm'; b.style='float:right'; b.textContent='🗑 Clear Activity';
      b.onclick=async()=>{const ok=await promptText('Type exactly: CLEAR ACTIVITY','CLEAR ACTIVITY');if(ok!=='CLEAR ACTIVITY')return;try{await api('/api/admin/clear-data',{method:'POST',body:{target:'activity'}});show('✅ Activity cleared.','success');loadActivityReal()}catch(err){show(`❌ ${err.message}`,'error')}};
      activityTitle.appendChild(b);
    }
  }

  function patchLabels(){
    document.querySelectorAll('button').forEach(btn=>{
      if (btn.textContent.includes('Sync Data')) btn.textContent=btn.textContent.replace('Sync Data','Verify Connection');
      if (btn.textContent.includes('Refresh Cache')) btn.textContent=btn.textContent.replace('Refresh Cache','Verify Connection');
    });
  }

  async function boot(){
    try { await api('/api/admin/me'); } catch(err){ location.href='/login.html'; return; }
    addHealthSummaryUI(); patchLabels();
    await loadSecurityReal();
    await loadDatabaseStatsReal();
    await loadActivityReal();
    setInterval(loadDatabaseStatsReal, 5000);
    setInterval(loadActivityReal, 15000);
    window.ScannerAPIReal.deleteAllDatabaseData = window.deleteAllDatabaseData;
    window.ScannerAPIReal.terminateAllSessions = window.terminateAllSessions;
    window.ScannerAPIReal.terminateSession = window.terminateSession;
    window.ScannerAPIReal.toggle2FA = window.toggle2FA;
    window.ScannerAPIReal.generateBackupCodes = window.generateBackupCodes;
    window.ScannerAPIReal.verifyOTP = window.verifyOTP;
    window.ScannerAPIReal.changeApiKeyWithVerification = window.changeApiKeyWithVerification;
    window.ScannerAPIReal.clearFirebase = window.clearFirebase;
    console.log('ScannerAPI: real server-side security layer active');
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
