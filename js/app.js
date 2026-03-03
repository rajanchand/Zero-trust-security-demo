// ============================================
// ZTS — Zero Trust Security Demo
// Frontend Application Logic
// ============================================

var currentUser = null;
var otpTimer = null;
var departments = [];
var allUsers = [];
var allDevices = [];
var allAuditLogs = [];
var allSessions = [];
var allIPRules = [];
var allPolicies = [];
var loginHistory = [];
var riskOverview = null;
var deviceFilter = 'all';
var auditFilter = 'all';
var sessionFilter = 'all';
var editingUserId = null;
var sessionTimerInterval = null;
var loginChart = null;
var riskChart = null;

// ===== SIDEBAR NAV CONFIG =====
var SIDEBAR_CONFIG = {
  SuperAdmin: [
    { label: 'OVERVIEW', items: [
      { id: 'dashboard', icon: 'fa-gauge-high', text: 'Dashboard' },
      { id: 'risk-overview', icon: 'fa-chart-pie', text: 'Risk Overview' }
    ]},
    { label: 'MANAGEMENT', items: [
      { id: 'users', icon: 'fa-users', text: 'User Management' },
      { id: 'devices', icon: 'fa-laptop-medical', text: 'Device Trust' },
      { id: 'sessions', icon: 'fa-tower-broadcast', text: 'Sessions' }
    ]},
    { label: 'SECURITY', items: [
      { id: 'audit', icon: 'fa-clipboard-list', text: 'Audit Logs' },
      { id: 'login-history', icon: 'fa-clock-rotate-left', text: 'Login History' },
      { id: 'suspicious', icon: 'fa-triangle-exclamation', text: 'Suspicious Activity' },
      { id: 'ip-rules', icon: 'fa-network-wired', text: 'IP Rules' },
      { id: 'policies', icon: 'fa-sliders', text: 'Security Policies' }
    ]}
  ],
  HR: [
    { label: 'HR PORTAL', items: [
      { id: 'dashboard', icon: 'fa-gauge-high', text: 'Dashboard' },
      { id: 'users', icon: 'fa-users', text: 'Employee Directory' }
    ]}
  ],
  Finance: [
    { label: 'FINANCE PORTAL', items: [
      { id: 'dashboard', icon: 'fa-gauge-high', text: 'Dashboard' }
    ]}
  ],
  IT: [
    { label: 'IT PORTAL', items: [
      { id: 'dashboard', icon: 'fa-gauge-high', text: 'Dashboard' },
      { id: 'devices', icon: 'fa-laptop-medical', text: 'Device Logs' },
      { id: 'sessions', icon: 'fa-tower-broadcast', text: 'Sessions' }
    ]}
  ],
  CustomerSupport: [
    { label: 'SUPPORT PORTAL', items: [
      { id: 'dashboard', icon: 'fa-gauge-high', text: 'Dashboard' }
    ]}
  ]
};

// ===== PAGE LOAD =====
document.addEventListener('DOMContentLoaded', async function () {
  var saved = sessionStorage.getItem('zt_session');
  if (saved) {
    try {
      currentUser = JSON.parse(saved);
      showApp();
    } catch (e) { sessionStorage.removeItem('zt_session'); }
  }

  // Login form
  document.getElementById('login-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var email = document.getElementById('email').value.trim();
    var password = document.getElementById('password').value;
    var err = document.getElementById('login-error');
    err.classList.add('hide');
    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
      });
      var data = await res.json();
      if (!res.ok) { err.textContent = data.error || 'Login failed'; err.classList.remove('hide'); return; }
      currentUser = { userId: data.userId, email: data.email, name: data.name, role: data.role };
      document.getElementById('otp-email-display').textContent = data.email;
      showPage('otp-page'); startOtpTimer();
    } catch (e) { err.textContent = 'Server unavailable'; err.classList.remove('hide'); }
  });

  // OTP inputs
  var otpBoxes = document.querySelectorAll('.otp-input');
  for (var i = 0; i < otpBoxes.length; i++) {
    (function (idx) {
      otpBoxes[idx].addEventListener('input', function () {
        this.value = this.value.replace(/[^0-9]/g, '');
        if (this.value && idx < otpBoxes.length - 1) otpBoxes[idx + 1].focus();
        this.classList.toggle('ok', !!this.value);
      });
      otpBoxes[idx].addEventListener('keydown', function (e) {
        if (e.key === 'Backspace' && !this.value && idx > 0) {
          otpBoxes[idx - 1].focus(); otpBoxes[idx - 1].value = ''; otpBoxes[idx - 1].classList.remove('ok');
        }
      });
    })(i);
  }

  // OTP verify
  document.getElementById('otp-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var err = document.getElementById('otp-error'); err.classList.add('hide');
    var code = '';
    for (var i = 0; i < otpBoxes.length; i++) code += otpBoxes[i].value;
    if (code.length < 6) { err.textContent = 'Enter all 6 digits'; err.classList.remove('hide'); return; }
    clearInterval(otpTimer);
    var deviceInfo = getDeviceInfo();
    var ipInfo = await fetchIPInfo();
    deviceInfo.ipAddress = ipInfo.ip; deviceInfo.geoLocation = ipInfo.geo;
    deviceInfo.country = ipInfo.country; deviceInfo.city = ipInfo.city;
    try {
      var res = await fetch('/api/auth/verify-otp', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: currentUser.userId, code: code, deviceInfo: deviceInfo })
      });
      var data = await res.json();
      if (!res.ok) {
        for (var j = 0; j < otpBoxes.length; j++) { otpBoxes[j].classList.add('err'); otpBoxes[j].classList.remove('ok'); }
        err.textContent = data.error || 'Invalid'; err.classList.remove('hide');
        setTimeout(function () { for (var k = 0; k < otpBoxes.length; k++) { otpBoxes[k].classList.remove('err'); otpBoxes[k].value = ''; } otpBoxes[0].focus(); }, 600);
        return;
      }
      currentUser = data.user;
      sessionStorage.setItem('zt_session', JSON.stringify(currentUser));
      // Device check
      try {
        var devRes = await fetch('/api/devices/request', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userId: currentUser._id, userEmail: currentUser.email, userName: currentUser.name,
            ipAddress: deviceInfo.ipAddress, geoLocation: deviceInfo.geoLocation, deviceHealth: deviceInfo.deviceHealth,
            browser: deviceInfo.browser, os: deviceInfo.os, fingerprint: deviceInfo.fingerprint })
        });
        var devData = await devRes.json();
        if (devData.approved === false && currentUser.role !== 'SuperAdmin') {
          document.getElementById('pending-ip').textContent = deviceInfo.ipAddress || '—';
          document.getElementById('pending-geo').textContent = deviceInfo.geoLocation || '—';
          document.getElementById('pending-browser').textContent = deviceInfo.browser || '—';
          document.getElementById('pending-health').textContent = deviceInfo.deviceHealth || '—';
          showPage('device-pending-page'); return;
        }
      } catch (de) { console.error('Device check:', de); }
      showApp();
    } catch (e) { err.textContent = 'Verification failed'; err.classList.remove('hide'); }
  });

  // Resend OTP
  document.getElementById('resend-btn').addEventListener('click', async function (e) {
    e.preventDefault();
    if (!currentUser) return;
    this.textContent = 'Sending...';
    try {
      await fetch('/api/auth/resend-otp', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: currentUser.email }) });
      this.textContent = 'Code Resent ✓'; startOtpTimer();
    } catch (e) { this.textContent = 'Failed'; }
    var self = this; setTimeout(function () { self.textContent = 'Resend Code'; }, 3000);
  });

  document.getElementById('back-btn').addEventListener('click', function (e) { e.preventDefault(); clearInterval(otpTimer); showPage('login-page'); });

  // Profile form
  document.getElementById('profile-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('profile-msg'); msg.classList.add('hide');
    try {
      var res = await fetch('/api/auth/profile/' + currentUser._id, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: document.getElementById('profile-name').value.trim(), phone: document.getElementById('profile-phone').value.trim(), gender: document.getElementById('profile-gender').value })
      });
      var data = await res.json();
      if (!res.ok) { msg.textContent = data.error; msg.className = 'profile-msg err'; return; }
      currentUser.name = data.user.name; currentUser.phone = data.user.phone; currentUser.gender = data.user.gender;
      sessionStorage.setItem('zt_session', JSON.stringify(currentUser));
      document.getElementById('sidebar-user-name').textContent = currentUser.name;
      document.getElementById('sidebar-avatar-letter').textContent = currentUser.name.charAt(0).toUpperCase();
      msg.textContent = 'Profile updated ✓'; msg.className = 'profile-msg success';
    } catch (e) { msg.textContent = 'Server error'; msg.className = 'profile-msg err'; }
  });

  // Password form
  document.getElementById('password-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('pw-msg'); msg.classList.add('hide');
    var newPw = document.getElementById('pw-new').value;
    if (newPw.length < 6) { msg.textContent = 'Min 6 characters'; msg.className = 'profile-msg err'; return; }
    try {
      var res = await fetch('/api/auth/profile/' + currentUser._id, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: document.getElementById('pw-current').value, newPassword: newPw })
      });
      var data = await res.json();
      if (!res.ok) { msg.textContent = data.error; msg.className = 'profile-msg err'; return; }
      msg.textContent = 'Password updated ✓'; msg.className = 'profile-msg success'; this.reset();
    } catch (e) { msg.textContent = 'Server error'; msg.className = 'profile-msg err'; }
  });

  // Create user form
  document.getElementById('create-user-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    try {
      var res = await fetch('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: document.getElementById('new-name').value.trim(), email: document.getElementById('new-email').value.trim(),
          password: document.getElementById('new-password').value, role: document.getElementById('new-role').value, department: document.getElementById('new-dept').value })
      });
      if (!res.ok) { var e2 = await res.json(); alert(e2.error); return; }
      await loadUsers(); closeModal('create-user-modal'); this.reset();
    } catch (e) { alert('Failed'); }
  });

  // Edit user form
  document.getElementById('edit-user-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    try {
      var res = await fetch('/api/users/' + editingUserId, { method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: document.getElementById('edit-name').value.trim(), email: document.getElementById('edit-email').value.trim(),
          role: document.getElementById('edit-role-select').value, department: document.getElementById('edit-dept-select').value,
          status: document.getElementById('edit-status-select').value, mfa: document.getElementById('edit-mfa').checked })
      });
      if (!res.ok) { var e2 = await res.json(); alert(e2.error); return; }
      await loadUsers(); closeModal('edit-user-modal');
    } catch (e) { alert('Failed'); }
  });

  // Modal close on overlay
  document.querySelectorAll('.modal-overlay').forEach(function (el) {
    el.addEventListener('click', function (e) { if (e.target === this) this.classList.add('hide'); });
  });
});

// ===== HELPERS =====
function showPage(id) { document.querySelectorAll('.page').forEach(function (p) { p.classList.remove('active'); }); document.getElementById(id).classList.add('active'); }
function openModal(id) { document.getElementById(id).classList.remove('hide'); }
function closeModal(id) { document.getElementById(id).classList.add('hide'); }
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('open'); }
function logout() { currentUser = null; clearInterval(sessionTimerInterval); sessionStorage.removeItem('zt_session'); showPage('login-page'); document.getElementById('login-form').reset(); }

function startOtpTimer() {
  var secs = 60; document.getElementById('otp-timer').textContent = secs;
  clearInterval(otpTimer);
  otpTimer = setInterval(function () { secs--; document.getElementById('otp-timer').textContent = secs; if (secs <= 0) clearInterval(otpTimer); }, 1000);
}

function formatDate(d) {
  if (!d) return '—';
  var dt = new Date(d);
  return dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) + ' ' + dt.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

function getDeviceInfo() {
  var ua = navigator.userAgent; var browser = 'Unknown'; var os = 'Unknown';
  if (ua.indexOf('Edg') > -1) browser = 'Edge';
  else if (ua.indexOf('Chrome') > -1) browser = 'Chrome';
  else if (ua.indexOf('Firefox') > -1) browser = 'Firefox';
  else if (ua.indexOf('Safari') > -1) browser = 'Safari';
  if (ua.indexOf('Windows') > -1) os = 'Windows'; else if (ua.indexOf('Mac') > -1) os = 'macOS';
  else if (ua.indexOf('Linux') > -1) os = 'Linux'; else if (ua.indexOf('Android') > -1) os = 'Android';
  else if (/iPhone|iPad/.test(ua)) os = 'iOS';
  var health = location.protocol !== 'https:' ? 'Poor — Not HTTPS' : !navigator.cookieEnabled ? 'Fair — Cookies disabled' : 'Good';
  var fp = btoa(ua + screen.width + screen.height + navigator.language + new Date().getTimezoneOffset()).substring(0, 32);
  return { browser: browser + ' (' + os + ')', os: os, deviceHealth: health, fingerprint: fp, ipAddress: '', geoLocation: '', country: '', city: '' };
}

async function fetchIPInfo() {
  try { var r = await fetch('https://ipapi.co/json/'); var d = await r.json();
    return { ip: d.ip || '', geo: (d.city || '') + ', ' + (d.region || '') + ', ' + (d.country_name || ''), country: d.country_name || '', city: d.city || '' };
  } catch (e) { return { ip: '', geo: '', country: '', city: '' }; }
}

// ===== SHOW APP =====
async function showApp() {
  if (!currentUser) return;
  showPage('app-page');
  buildSidebar();
  document.getElementById('sidebar-user-name').textContent = currentUser.name;
  document.getElementById('sidebar-user-role').textContent = currentUser.role;
  document.getElementById('sidebar-avatar-letter').textContent = currentUser.name.charAt(0).toUpperCase();
  startSessionTimer();
  navigateTo('dashboard');
}

function buildSidebar() {
  var nav = document.getElementById('sidebar-nav');
  var role = currentUser.role;
  var config = SIDEBAR_CONFIG[role] || SIDEBAR_CONFIG['CustomerSupport'];
  var html = '';
  for (var g = 0; g < config.length; g++) {
    html += '<div class="nav-label">' + config[g].label + '</div>';
    for (var i = 0; i < config[g].items.length; i++) {
      var item = config[g].items[i];
      html += '<a href="#" data-page="' + item.id + '" onclick="navigateTo(\'' + item.id + '\');return false;">'
        + '<i class="fas ' + item.icon + '"></i> ' + item.text + '</a>';
    }
  }
  nav.innerHTML = html;
}

async function navigateTo(pageId) {
  // Update sidebar active
  document.querySelectorAll('.sidebar-nav a').forEach(function (a) { a.classList.toggle('active', a.dataset.page === pageId); });
  document.getElementById('sidebar').classList.remove('open');
  var area = document.getElementById('content-area');
  var title = document.getElementById('page-title');

  if (pageId === 'dashboard') { title.textContent = 'Dashboard'; await renderDashboard(area); }
  else if (pageId === 'risk-overview') { title.textContent = 'Risk Overview'; await renderRiskOverview(area); }
  else if (pageId === 'users') { title.textContent = 'User Management'; await renderUsers(area); }
  else if (pageId === 'devices') { title.textContent = 'Device Trust'; await renderDevices(area); }
  else if (pageId === 'sessions') { title.textContent = 'Sessions'; await renderSessions(area); }
  else if (pageId === 'audit') { title.textContent = 'Audit Logs'; await renderAudit(area); }
  else if (pageId === 'login-history') { title.textContent = 'Login History'; await renderLoginHistory(area); }
  else if (pageId === 'suspicious') { title.textContent = 'Suspicious Activity'; await renderSuspicious(area); }
  else if (pageId === 'ip-rules') { title.textContent = 'IP Access Rules'; await renderIPRules(area); }
  else if (pageId === 'policies') { title.textContent = 'Security Policies'; await renderPolicies(area); }
}

// ===== DASHBOARD =====
async function renderDashboard(area) {
  await Promise.all([loadUsers(), loadDepartments(), loadDevices(), loadAuditLogs(), loadSessions()]);
  if (riskOverview === null) { try { var r = await fetch('/api/risk/overview'); riskOverview = await r.json(); } catch(e) { riskOverview = { distribution: {low:0,medium:0,high:0}, dailyLogins: {}, highRiskUsers: [], totalUsers: 0 }; } }
  var isSA = currentUser.role === 'SuperAdmin';
  var pendingDevices = 0; for (var i = 0; i < allDevices.length; i++) { if (allDevices[i].status === 'Pending') pendingDevices++; }
  var activeSessions = 0; for (var i = 0; i < allSessions.length; i++) { if (allSessions[i].is_active && new Date(allSessions[i].expires_at) > new Date()) activeSessions++; }
  var warnings24 = 0, critical24 = 0, now = Date.now();
  for (var i = 0; i < allAuditLogs.length; i++) { if (now - new Date(allAuditLogs[i].created_at).getTime() < 86400000) { if (allAuditLogs[i].severity === 'warning') warnings24++; if (allAuditLogs[i].severity === 'critical') critical24++; } }

  var html = '<div class="welcome-banner"><div><h2>Welcome, ' + currentUser.name + ' 👋</h2><p>' + currentUser.role + ' • ' + (currentUser.department || 'General') + '</p></div>'
    + '<span class="welcome-badge"><i class="fas fa-shield-halved"></i> Zero Trust Protected</span></div>';

  if (isSA) {
    html += '<div class="stats-grid">'
      + statCard('fa-users', 'blue', allUsers.length, 'Total Users')
      + statCard('fa-tower-broadcast', 'green', activeSessions, 'Active Sessions')
      + statCard('fa-laptop-medical', 'orange', pendingDevices, 'Pending Devices')
      + statCard('fa-triangle-exclamation', 'red', critical24, 'Critical (24h)')
      + statCard('fa-exclamation', 'orange', warnings24, 'Warnings (24h)')
      + statCard('fa-skull-crossbones', 'purple', riskOverview.distribution.high, 'High Risk Users')
      + '</div>';
    html += '<div class="charts-grid">'
      + '<div class="section-card"><h3><i class="fas fa-chart-bar"></i> Login Attempts (7 Days)</h3><div class="chart-container"><canvas id="loginChart"></canvas></div></div>'
      + '<div class="section-card"><h3><i class="fas fa-chart-pie"></i> Risk Distribution</h3><div class="chart-container"><canvas id="riskChart"></canvas></div></div>'
      + '</div>';
  } else {
    // User dashboard
    var score = currentUser.riskScore || 0;
    var level = score <= 30 ? 'low' : score <= 60 ? 'medium' : 'high';
    var levelLabel = score <= 30 ? 'Low Risk' : score <= 60 ? 'Medium Risk' : 'High Risk';
    html += '<div class="stats-grid">'
      + statCard('fa-shield-halved', level === 'low' ? 'green' : level === 'medium' ? 'orange' : 'red', score + '/100', 'Trust Score')
      + statCard('fa-user', 'blue', currentUser.role, 'Your Role')
      + statCard('fa-building', 'purple', currentUser.department || 'General', 'Department')
      + statCard('fa-clock', 'cyan', currentUser.createdAt ? formatDate(currentUser.createdAt).split(' ')[0] : '—', 'Member Since')
      + '</div>';
    html += '<div class="section-card"><h3><i class="fas fa-gauge-high"></i> Your Trust Score — ' + levelLabel + '</h3>'
      + '<div class="risk-score-big" style="color:' + (level === 'low' ? '#22c55e' : level === 'medium' ? '#f59e0b' : '#ef4444') + '">' + score + '</div>'
      + '<div class="risk-gauge-bar"><div class="risk-gauge-fill ' + level + '" style="width:' + score + '%"></div></div>';
    if (currentUser.riskFactors && currentUser.riskFactors.length) {
      html += '<div class="risk-factors-list">';
      for (var i = 0; i < currentUser.riskFactors.length; i++) {
        var f = currentUser.riskFactors[i];
        html += '<span class="risk-factor-tag"><i class="fas ' + (f.points === 0 ? 'fa-circle-check' : 'fa-circle-minus') + '" style="color:' + (f.points === 0 ? '#22c55e' : '#ef4444') + '"></i> ' + f.factor + ': ' + f.detail + '</span>';
      }
      html += '</div>';
    }
    html += '</div>';
    // Security alerts
    html += '<div class="section-card"><h3><i class="fas fa-bell"></i> Security Alerts</h3>';
    if (currentUser.vpnDetected) html += '<div class="alert-item warning"><i class="fas fa-eye-slash"></i> VPN/Proxy detected on your connection</div>';
    if (currentUser.impossibleTravel) html += '<div class="alert-item critical"><i class="fas fa-plane"></i> Impossible travel detected — location changed too quickly</div>';
    if (score > 60) html += '<div class="alert-item critical"><i class="fas fa-shield-halved"></i> High risk score — additional verification may be required</div>';
    if (score <= 30 && !currentUser.vpnDetected) html += '<div class="alert-item info"><i class="fas fa-circle-check"></i> All security checks passed — low risk profile</div>';
    html += '</div>';
    // Device info
    var di = getDeviceInfo();
    html += '<div class="section-card"><h3><i class="fas fa-laptop"></i> Current Device</h3>'
      + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:13px">'
      + '<div><strong>Browser:</strong> ' + di.browser + '</div>'
      + '<div><strong>OS:</strong> ' + di.os + '</div>'
      + '<div><strong>Health:</strong> ' + di.deviceHealth + '</div>'
      + '<div><strong>Fingerprint:</strong> <code>' + di.fingerprint.substring(0,12) + '...</code></div>'
      + '</div></div>';
  }
  area.innerHTML = html;

  // Render charts for SuperAdmin
  if (isSA) { renderLoginChart(); renderRiskChart(); }
}

function statCard(icon, color, value, label) {
  return '<div class="stat-card"><div class="stat-icon ' + color + '"><i class="fas ' + icon + '"></i></div>'
    + '<div class="stat-info"><div class="stat-value">' + value + '</div><div class="stat-label">' + label + '</div></div></div>';
}

function renderLoginChart() {
  var ctx = document.getElementById('loginChart');
  if (!ctx || !riskOverview) return;
  var labels = [], success = [], failed = [];
  var days = riskOverview.dailyLogins || {};
  // Last 7 days
  for (var i = 6; i >= 0; i--) {
    var d = new Date(Date.now() - i * 86400000).toISOString().split('T')[0];
    labels.push(d.substring(5));
    success.push(days[d] ? days[d].success : 0);
    failed.push(days[d] ? days[d].failed : 0);
  }
  if (loginChart) loginChart.destroy();
  loginChart = new Chart(ctx, { type: 'bar', data: {
    labels: labels,
    datasets: [
      { label: 'Success', data: success, backgroundColor: '#22c55e', borderRadius: 4 },
      { label: 'Failed', data: failed, backgroundColor: '#ef4444', borderRadius: 4 }
    ]
  }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } }, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } } });
}

function renderRiskChart() {
  var ctx = document.getElementById('riskChart');
  if (!ctx || !riskOverview) return;
  if (riskChart) riskChart.destroy();
  riskChart = new Chart(ctx, { type: 'doughnut', data: {
    labels: ['Low (0-30)', 'Medium (31-60)', 'High (61-100)'],
    datasets: [{ data: [riskOverview.distribution.low, riskOverview.distribution.medium, riskOverview.distribution.high],
      backgroundColor: ['#22c55e', '#f59e0b', '#ef4444'], borderWidth: 0 }]
  }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } } });
}

// ===== DATA LOADERS =====
async function loadUsers() { try { var r = await fetch('/api/users'); allUsers = await r.json(); } catch(e){} }
async function loadDepartments() { try { var r = await fetch('/api/departments'); departments = await r.json(); populateDeptDropdowns(); } catch(e){} }
async function loadDevices() { try { var r = await fetch('/api/devices'); allDevices = await r.json(); } catch(e){} }
async function loadAuditLogs() { try { var r = await fetch('/api/audit'); allAuditLogs = await r.json(); } catch(e){} }
async function loadSessions() { try { var r = await fetch('/api/sessions'); allSessions = await r.json(); } catch(e){} }
async function loadIPRules() { try { var r = await fetch('/api/ip-rules'); allIPRules = await r.json(); } catch(e){} }
async function loadPolicies() { try { var r = await fetch('/api/policies'); allPolicies = await r.json(); } catch(e){} }

function populateDeptDropdowns() {
  var dd = document.getElementById('new-dept'); if (!dd) return;
  dd.innerHTML = ''; for (var i = 0; i < departments.length; i++) dd.innerHTML += '<option value="' + departments[i].name + '">' + departments[i].name + '</option>';
}

// ===== RISK OVERVIEW PAGE =====
async function renderRiskOverview(area) {
  try { var r = await fetch('/api/risk/overview'); riskOverview = await r.json(); } catch(e) { riskOverview = { distribution:{low:0,medium:0,high:0}, dailyLogins:{}, highRiskUsers:[], totalUsers:0 }; }
  var html = '<div class="stats-grid">'
    + statCard('fa-check-circle', 'green', riskOverview.distribution.low, 'Low Risk (0-30)')
    + statCard('fa-exclamation-circle', 'orange', riskOverview.distribution.medium, 'Medium Risk (31-60)')
    + statCard('fa-skull-crossbones', 'red', riskOverview.distribution.high, 'High Risk (61-100)')
    + '</div>';
  html += '<div class="charts-grid">'
    + '<div class="section-card"><h3><i class="fas fa-chart-pie"></i> Risk Distribution</h3><div class="chart-container"><canvas id="riskChart"></canvas></div></div>'
    + '<div class="section-card"><h3><i class="fas fa-chart-bar"></i> Login Attempts (7 Days)</h3><div class="chart-container"><canvas id="loginChart"></canvas></div></div>'
    + '</div>';
  if (riskOverview.highRiskUsers && riskOverview.highRiskUsers.length) {
    html += '<div class="section-card"><h3><i class="fas fa-user-slash"></i> High Risk Users</h3><table class="data-table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Risk Score</th><th>Status</th></tr></thead><tbody>';
    for (var i = 0; i < riskOverview.highRiskUsers.length; i++) {
      var u = riskOverview.highRiskUsers[i];
      html += '<tr><td><strong>' + u.name + '</strong></td><td>' + u.email + '</td><td><span class="badge blue">' + u.role + '</span></td>'
        + '<td><span class="badge red">' + (u.last_risk_score||0) + '</span></td>'
        + '<td>' + (u.is_blocked ? '<span class="badge red">Blocked</span>' : '<span class="badge green">Active</span>') + '</td></tr>';
    }
    html += '</tbody></table></div>';
  }
  area.innerHTML = html;
  renderRiskChart(); renderLoginChart();
}

// ===== USERS PAGE =====
async function renderUsers(area) {
  await loadUsers(); await loadDepartments();
  var html = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">'
    + '<div><strong>' + allUsers.length + '</strong> users</div>'
    + '<button class="btn-primary sm" onclick="openModal(\'create-user-modal\')"><i class="fas fa-plus"></i> New User</button></div>';
  html += '<div class="section-card" style="padding:0;overflow:auto"><table class="data-table"><thead><tr>'
    + '<th>User</th><th>Role</th><th>Department</th><th>Status</th><th>MFA</th><th>Risk</th><th>Last Login</th><th>Actions</th></tr></thead><tbody>';
  if (!allUsers.length) { html += '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:40px">No users found</td></tr>'; }
  for (var i = 0; i < allUsers.length; i++) {
    var u = allUsers[i];
    var riskBadge = (u.lastRiskScore||0) <= 30 ? 'green' : (u.lastRiskScore||0) <= 60 ? 'orange' : 'red';
    html += '<tr><td><strong>' + u.name + '</strong><br><small style="color:#94a3b8">' + u.email + '</small></td>'
      + '<td><span class="badge blue">' + u.role + '</span></td>'
      + '<td>' + (u.department||'—') + '</td>'
      + '<td><span class="badge ' + (u.status==='Active'?'green':'red') + '">' + (u.isBlocked ? 'Blocked' : u.status) + '</span></td>'
      + '<td>' + (u.mfa ? '<span class="badge green">On</span>' : '<span class="badge gray">Off</span>') + '</td>'
      + '<td><span class="badge ' + riskBadge + '">' + (u.lastRiskScore||0) + '</span></td>'
      + '<td>' + formatDate(u.lastLoginAt) + '</td>'
      + '<td class="table-actions">'
      + '<button class="btn-icon" onclick="editUser(\'' + u._id + '\')"><i class="fas fa-pen"></i></button>'
      + '<button class="btn-icon ' + (u.isBlocked?'success':'danger') + '" onclick="toggleBlock(\'' + u._id + '\',' + !u.isBlocked + ')"><i class="fas ' + (u.isBlocked?'fa-lock-open':'fa-ban') + '"></i></button>'
      + '<button class="btn-icon" onclick="resetPassword(\'' + u._id + '\')"><i class="fas fa-key"></i></button>'
      + '<button class="btn-icon" onclick="forceLogout(\'' + u._id + '\')"><i class="fas fa-right-from-bracket"></i></button>'
      + '<button class="btn-icon danger" onclick="deleteUser(\'' + u._id + '\')"><i class="fas fa-trash"></i></button>'
      + '</td></tr>';
  }
  html += '</tbody></table></div>';
  area.innerHTML = html;
}

function editUser(id) {
  var u = allUsers.find(function(x){return x._id===id;}); if (!u) return;
  editingUserId = id;
  document.getElementById('edit-name').value = u.name;
  document.getElementById('edit-email').value = u.email;
  document.getElementById('edit-role-select').value = u.role;
  document.getElementById('edit-status-select').value = u.status;
  document.getElementById('edit-mfa').checked = u.mfa;
  var sel = document.getElementById('edit-dept-select'); sel.innerHTML = '';
  for (var i = 0; i < departments.length; i++) sel.innerHTML += '<option value="' + departments[i].name + '"' + (departments[i].name===u.department?' selected':'') + '>' + departments[i].name + '</option>';
  openModal('edit-user-modal');
}
async function deleteUser(id) { if (!confirm('Delete?')) return; await fetch('/api/users/'+id,{method:'DELETE'}); navigateTo('users'); }
async function toggleBlock(id,block) { if (!confirm(block?'Block user?':'Unblock user?')) return; await fetch('/api/users/'+id+'/block',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({blocked:block})}); navigateTo('users'); }
async function resetPassword(id) { if (!confirm('Reset password to default?')) return; await fetch('/api/users/'+id+'/reset-password',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({})}); alert('Password reset'); }
async function forceLogout(id) { if (!confirm('Force logout?')) return; await fetch('/api/sessions/force-logout/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({revokedBy:currentUser.email})}); alert('User logged out'); }

// ===== DEVICES PAGE =====
async function renderDevices(area) {
  await loadDevices(); deviceFilter = 'all';
  var html = '<div class="filter-bar">'
    + '<button class="filter-btn active" onclick="filterDevicesUI(\'all\',this)">All</button>'
    + '<button class="filter-btn" onclick="filterDevicesUI(\'Pending\',this)">Pending</button>'
    + '<button class="filter-btn" onclick="filterDevicesUI(\'Approved\',this)">Approved</button>'
    + '<button class="filter-btn" onclick="filterDevicesUI(\'Rejected\',this)">Rejected</button></div>';
  html += '<div class="section-card" style="padding:0;overflow:auto"><table class="data-table" id="devices-table"><thead><tr>'
    + '<th>User</th><th>IP</th><th>Location</th><th>Health</th><th>Browser</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead><tbody id="devices-tbody"></tbody></table></div>';
  area.innerHTML = html;
  renderDevicesTable();
}
function renderDevicesTable() {
  var tbody = document.getElementById('devices-tbody'); if (!tbody) return;
  var list = deviceFilter === 'all' ? allDevices : allDevices.filter(function(d){return d.status===deviceFilter;});
  if (!list.length) { tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:40px">No devices found</td></tr>'; return; }
  var html = '';
  for (var i = 0; i < list.length; i++) {
    var d = list[i];
    var sc = d.status==='Approved'?'green':d.status==='Rejected'?'red':'orange';
    var hc = (d.device_health||'').indexOf('Poor')>-1?'red':(d.device_health||'').indexOf('Fair')>-1?'orange':'green';
    var acts = '';
    if (d.status === 'Pending') acts = '<button class="btn-icon success" onclick="approveDevice(\''+d.id+'\')"><i class="fas fa-check"></i></button><button class="btn-icon danger" onclick="rejectDevice(\''+d.id+'\')"><i class="fas fa-times"></i></button>';
    acts += '<button class="btn-icon danger" onclick="deleteDevice(\''+d.id+'\')"><i class="fas fa-trash"></i></button>';
    html += '<tr><td><strong>'+(d.user_name||'—')+'</strong><br><small style="color:#94a3b8">'+(d.user_email||'')+'</small></td>'
      + '<td><code>'+(d.ip_address||'—')+'</code></td><td>'+(d.geo_location||'—')+'</td>'
      + '<td><span class="badge '+hc+'">'+(d.device_health||'—')+'</span></td><td>'+(d.browser||'—')+'</td>'
      + '<td><span class="badge '+sc+'">'+d.status+'</span></td><td>'+formatDate(d.created_at)+'</td>'
      + '<td class="table-actions">'+acts+'</td></tr>';
  }
  tbody.innerHTML = html;
}
function filterDevicesUI(status, btn) { deviceFilter = status; renderDevicesTable(); document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');}); btn.classList.add('active'); }
async function approveDevice(id) { if (!confirm('Approve?')) return; await fetch('/api/devices/'+id+'/approve',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({approvedBy:currentUser.email})}); await loadDevices(); renderDevicesTable(); }
async function rejectDevice(id) { if (!confirm('Reject?')) return; await fetch('/api/devices/'+id+'/reject',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({approvedBy:currentUser.email})}); await loadDevices(); renderDevicesTable(); }
async function deleteDevice(id) { if (!confirm('Delete?')) return; await fetch('/api/devices/'+id,{method:'DELETE'}); await loadDevices(); renderDevicesTable(); }

// ===== SESSIONS PAGE =====
async function renderSessions(area) {
  await loadSessions(); sessionFilter = 'all';
  var html = '<div class="filter-bar">'
    + '<button class="filter-btn active" onclick="filterSessionsUI(\'all\',this)">All</button>'
    + '<button class="filter-btn" onclick="filterSessionsUI(\'active\',this)">Active</button>'
    + '<button class="filter-btn" onclick="filterSessionsUI(\'expired\',this)">Expired</button></div>';
  html += '<div class="section-card" style="padding:0;overflow:auto"><table class="data-table"><thead><tr>'
    + '<th>User</th><th>IP</th><th>Location</th><th>Browser</th><th>Created</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead><tbody id="sessions-tbody"></tbody></table></div>';
  area.innerHTML = html;
  renderSessionsTable();
}
function renderSessionsTable() {
  var tbody = document.getElementById('sessions-tbody'); if (!tbody) return;
  var list = allSessions;
  if (sessionFilter === 'active') list = allSessions.filter(function(s){return s.is_active && new Date(s.expires_at)>new Date();});
  else if (sessionFilter === 'expired') list = allSessions.filter(function(s){return !s.is_active || new Date(s.expires_at)<=new Date();});
  if (!list.length) { tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#94a3b8;padding:40px">No sessions</td></tr>'; return; }
  var html = '';
  for (var i = 0; i < list.length; i++) {
    var s = list[i]; var active = s.is_active && new Date(s.expires_at)>new Date();
    var badge = s.revoked_by ? '<span class="badge red"><i class="fas fa-ban"></i> Revoked</span>' : active ? '<span class="badge green">Active</span>' : '<span class="badge gray">Expired</span>';
    html += '<tr><td><strong>'+(s.user_name||'—')+'</strong><br><small style="color:#94a3b8">'+(s.user_email||'')+'</small></td>'
      + '<td><code>'+(s.ip_address||'—')+'</code></td><td>'+(s.geo_location||'—')+'</td><td>'+(s.browser||'—')+'</td>'
      + '<td>'+formatDate(s.created_at)+'</td><td>'+formatDate(s.expires_at)+'</td><td>'+badge+'</td>'
      + '<td>'+(active?'<button class="btn-icon danger" onclick="revokeSession(\''+s.id+'\')"><i class="fas fa-ban"></i></button>':'')+'</td></tr>';
  }
  tbody.innerHTML = html;
}
function filterSessionsUI(status, btn) { sessionFilter = status; renderSessionsTable(); document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');}); btn.classList.add('active'); }
async function revokeSession(id) { if (!confirm('Revoke?')) return; await fetch('/api/sessions/'+id+'/revoke',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({revokedBy:currentUser.email})}); await loadSessions(); renderSessionsTable(); }

// ===== AUDIT LOGS PAGE =====
async function renderAudit(area) {
  await loadAuditLogs(); auditFilter = 'all';
  var html = '<div class="filter-bar">'
    + '<button class="filter-btn active" onclick="filterAuditUI(\'all\',this)">All</button>'
    + '<button class="filter-btn" onclick="filterAuditUI(\'info\',this)"><i class="fas fa-circle-info"></i> Info</button>'
    + '<button class="filter-btn" onclick="filterAuditUI(\'warning\',this)"><i class="fas fa-triangle-exclamation"></i> Warning</button>'
    + '<button class="filter-btn" onclick="filterAuditUI(\'critical\',this)"><i class="fas fa-circle-exclamation"></i> Critical</button></div>';
  html += '<div class="section-card" style="padding:0;overflow:auto"><table class="data-table"><thead><tr>'
    + '<th>Severity</th><th>Event</th><th>User</th><th>IP</th><th>Details</th><th>Time</th></tr></thead><tbody id="audit-tbody"></tbody></table></div>';
  area.innerHTML = html;
  renderAuditTable();
}
function renderAuditTable() {
  var tbody = document.getElementById('audit-tbody'); if (!tbody) return;
  var list = auditFilter === 'all' ? allAuditLogs : allAuditLogs.filter(function(a){return a.severity===auditFilter;});
  if (!list.length) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:40px">No logs</td></tr>'; return; }
  var html = '';
  for (var i = 0; i < Math.min(list.length, 200); i++) {
    var a = list[i];
    var sc = a.severity==='critical'?'red':a.severity==='warning'?'orange':'blue';
    var ic = a.severity==='critical'?'fa-circle-exclamation':a.severity==='warning'?'fa-triangle-exclamation':'fa-circle-info';
    var label = (a.event_type||'').replace(/_/g,' ').replace(/\b\w/g,function(c){return c.toUpperCase();});
    html += '<tr><td><span class="badge '+sc+'"><i class="fas '+ic+'"></i> '+a.severity+'</span></td>'
      + '<td><strong>'+label+'</strong></td><td>'+(a.user_email||'—')+'</td>'
      + '<td><code>'+(a.ip_address||'—')+'</code></td><td>'+(a.details||'—')+'</td><td>'+formatDate(a.created_at)+'</td></tr>';
  }
  tbody.innerHTML = html;
}
function filterAuditUI(sev, btn) { auditFilter = sev; renderAuditTable(); document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');}); btn.classList.add('active'); }

// ===== LOGIN HISTORY PAGE =====
async function renderLoginHistory(area) {
  try { var r = await fetch('/api/risk/login-history'); loginHistory = await r.json(); } catch(e) { loginHistory = []; }
  var html = '<div class="section-card" style="padding:0;overflow:auto"><table class="data-table"><thead><tr>'
    + '<th>User</th><th>IP</th><th>Country</th><th>Browser</th><th>Risk</th><th>VPN</th><th>Suspicious</th><th>Success</th><th>Time</th></tr></thead><tbody>';
  if (!loginHistory.length) html += '<tr><td colspan="9" style="text-align:center;color:#94a3b8;padding:40px">No login history</td></tr>';
  for (var i = 0; i < loginHistory.length; i++) {
    var h = loginHistory[i];
    var rl = (h.risk_score||0)<=30?'green':(h.risk_score||0)<=60?'orange':'red';
    html += '<tr><td>'+(h.user_email||'—')+'</td><td><code>'+(h.ip_address||'—')+'</code></td>'
      + '<td>'+(h.country||'—')+'</td><td>'+(h.browser||'—')+'</td>'
      + '<td><span class="badge '+rl+'">'+(h.risk_score||0)+'</span></td>'
      + '<td>'+(h.vpn_detected?'<span class="badge orange">Yes</span>':'<span class="badge gray">No</span>')+'</td>'
      + '<td>'+(h.is_suspicious?'<span class="badge red">Yes</span>':'<span class="badge gray">No</span>')+'</td>'
      + '<td>'+(h.login_success?'<span class="badge green">✓</span>':'<span class="badge red">✗</span>')+'</td>'
      + '<td>'+formatDate(h.created_at)+'</td></tr>';
  }
  html += '</tbody></table></div>';
  area.innerHTML = html;
}

// ===== SUSPICIOUS ACTIVITY PAGE =====
async function renderSuspicious(area) {
  var suspicious = [];
  try { var r = await fetch('/api/risk/suspicious'); suspicious = await r.json(); } catch(e) {}
  var html = '<div class="section-card"><h3><i class="fas fa-triangle-exclamation" style="color:#ef4444"></i> Suspicious Activities (' + suspicious.length + ')</h3>';
  if (!suspicious.length) { html += '<p style="color:#94a3b8;text-align:center;padding:20px">No suspicious activities detected</p>'; }
  else {
    html += '<table class="data-table"><thead><tr><th>User</th><th>IP</th><th>Country</th><th>Risk</th><th>VPN</th><th>Time</th></tr></thead><tbody>';
    for (var i = 0; i < suspicious.length; i++) {
      var s = suspicious[i];
      html += '<tr><td>'+(s.user_email||'—')+'</td><td><code>'+(s.ip_address||'—')+'</code></td>'
        + '<td>'+(s.country||'—')+'</td><td><span class="badge red">'+(s.risk_score||0)+'</span></td>'
        + '<td>'+(s.vpn_detected?'<span class="badge orange">Yes</span>':'No')+'</td>'
        + '<td>'+formatDate(s.created_at)+'</td></tr>';
    }
    html += '</tbody></table>';
  }
  html += '</div>';
  area.innerHTML = html;
}

// ===== IP RULES PAGE =====
async function renderIPRules(area) {
  await loadIPRules();
  var allowRules = allIPRules.filter(function(r){return r.rule_type==='allow';});
  var blockRules = allIPRules.filter(function(r){return r.rule_type==='block';});
  var html = '<div class="ip-grid">'
    + '<div class="ip-section"><h4><i class="fas fa-shield-halved" style="color:#22c55e"></i> IP Allowlist</h4>'
    + '<div class="ip-form"><input type="text" id="allow-ip-input" placeholder="e.g. 192.168.1.*"><input type="text" id="allow-ip-label" placeholder="Label">'
    + '<button class="btn-primary sm" onclick="addIPRule(\'allow\')">Add</button></div><ul class="ip-list" id="allow-ip-list">';
  for (var i = 0; i < allowRules.length; i++) html += ipRuleItem(allowRules[i]);
  if (!allowRules.length) html += '<li style="color:#94a3b8">No allowlist rules</li>';
  html += '</ul></div>';
  html += '<div class="ip-section"><h4><i class="fas fa-ban" style="color:#ef4444"></i> IP Blocklist</h4>'
    + '<div class="ip-form"><input type="text" id="block-ip-input" placeholder="e.g. 10.0.0.*"><input type="text" id="block-ip-label" placeholder="Label">'
    + '<button class="btn-primary sm" style="background:linear-gradient(135deg,#ef4444,#dc2626)" onclick="addIPRule(\'block\')">Add</button></div><ul class="ip-list" id="block-ip-list">';
  for (var i = 0; i < blockRules.length; i++) html += ipRuleItem(blockRules[i]);
  if (!blockRules.length) html += '<li style="color:#94a3b8">No blocklist rules</li>';
  html += '</ul></div></div>';
  area.innerHTML = html;
}
function ipRuleItem(r) {
  return '<li><code>'+r.ip_pattern+'</code>'+(r.label?' <small style="color:#94a3b8">'+r.label+'</small>':'')
    + '<button class="btn-icon danger" style="margin-left:auto" onclick="deleteIPRule(\''+r.id+'\')"><i class="fas fa-trash"></i></button></li>';
}
async function addIPRule(type) {
  var ip = document.getElementById(type+'-ip-input').value.trim();
  var label = document.getElementById(type+'-ip-label').value.trim();
  if (!ip) { alert('Enter an IP'); return; }
  var r = await fetch('/api/ip-rules',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip_pattern:ip,rule_type:type,label:label,created_by:currentUser.email})});
  if (!r.ok) { var e = await r.json(); alert(e.error); return; }
  navigateTo('ip-rules');
}
async function deleteIPRule(id) { if (!confirm('Delete?')) return; await fetch('/api/ip-rules/'+id,{method:'DELETE'}); navigateTo('ip-rules'); }

// ===== POLICIES PAGE =====
async function renderPolicies(area) {
  await loadPolicies();
  var cfg = {
    'session_timeout_minutes':{icon:'fa-clock',label:'Session Timeout (min)',type:'number'},
    'max_failed_logins':{icon:'fa-lock',label:'Max Failed Logins',type:'number'},
    'mfa_required':{icon:'fa-shield-halved',label:'MFA Required',type:'toggle'},
    'password_min_length':{icon:'fa-key',label:'Min Password Length',type:'number'},
    'device_approval_required':{icon:'fa-laptop-medical',label:'Device Approval Required',type:'toggle'},
    'ip_restriction_enabled':{icon:'fa-network-wired',label:'IP Restriction Enabled',type:'toggle'},
    'lockout_duration_minutes':{icon:'fa-hourglass-half',label:'Lockout Duration (min)',type:'number'}
  };
  var html = '<div class="section-card"><h3><i class="fas fa-sliders"></i> Security Policies</h3>';
  for (var i = 0; i < allPolicies.length; i++) {
    var p = allPolicies[i]; var c = cfg[p.policy_key] || {icon:'fa-cog',label:p.policy_key,type:'text'};
    if (c.type === 'toggle') {
      var on = p.policy_value === 'true';
      html += '<div class="policy-item"><div class="policy-info"><i class="fas '+c.icon+'"></i> '+c.label+'</div>'
        + '<label class="toggle"><input type="checkbox" '+(on?'checked':'')+' onchange="updatePolicy(\''+p.policy_key+'\',this.checked?\'true\':\'false\')"><span class="toggle-slider"></span></label></div>';
    } else {
      html += '<div class="policy-item"><div class="policy-info"><i class="fas '+c.icon+'"></i> '+c.label+'</div>'
        + '<input type="number" class="policy-input" value="'+p.policy_value+'" onchange="updatePolicy(\''+p.policy_key+'\',this.value)" min="1" max="999"></div>';
    }
  }
  html += '</div>';
  area.innerHTML = html;
}
async function updatePolicy(key, val) {
  var r = await fetch('/api/policies/'+key,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({value:val,updatedBy:currentUser.email})});
  if (!r.ok) { var e = await r.json(); alert(e.error); }
}

// ===== SESSION TIMER =====
function startSessionTimer() {
  if (!currentUser || !currentUser.sessionExpiresAt) return;
  var pill = document.getElementById('session-pill');
  var text = document.getElementById('session-timer-text');
  if (!pill || !text) return;
  clearInterval(sessionTimerInterval);
  sessionTimerInterval = setInterval(function () {
    var rem = new Date(currentUser.sessionExpiresAt).getTime() - Date.now();
    if (rem <= 0) { clearInterval(sessionTimerInterval); text.textContent = 'EXPIRED'; pill.classList.add('expired'); alert('Session expired'); logout(); return; }
    var m = Math.floor(rem / 60000); var s = Math.floor((rem % 60000) / 1000);
    text.textContent = String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0');
    if (rem < 300000) pill.classList.add('warning');
  }, 1000);
}

// ===== DEVICE CHECK =====
async function checkDeviceApproval() {
  if (!currentUser) return;
  var di = getDeviceInfo();
  try {
    var r = await fetch('/api/devices/check/' + currentUser._id + '/' + di.fingerprint);
    var result = await r.json();
    var msg = document.getElementById('device-pending-msg');
    if (result.approved) { msg.textContent = 'Device approved! Redirecting...'; msg.className = 'profile-msg success'; setTimeout(function(){ showApp(); }, 1000); }
    else { msg.textContent = 'Still pending approval.'; msg.className = 'profile-msg err'; }
  } catch(e) { console.error(e); }
}

// ===== PROFILE MODAL =====
function openProfileModal() {
  if (!currentUser) return;
  document.getElementById('profile-display-name').textContent = currentUser.name;
  document.getElementById('profile-display-role').textContent = currentUser.role + ' — ' + (currentUser.department || 'General');
  document.getElementById('profile-avatar-letter').textContent = currentUser.name.charAt(0).toUpperCase();
  document.getElementById('profile-name').value = currentUser.name;
  document.getElementById('profile-email').value = currentUser.email;
  document.getElementById('profile-phone').value = currentUser.phone || '';
  document.getElementById('profile-gender').value = currentUser.gender || '';
  document.getElementById('profile-department').value = currentUser.department || '';
  document.getElementById('profile-status').value = currentUser.status || '';
  document.getElementById('profile-msg').classList.add('hide');
  document.getElementById('pw-msg').classList.add('hide');
  openModal('profile-modal');
}
