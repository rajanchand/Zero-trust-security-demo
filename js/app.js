// global variables
var currentUser = null;
var otpTimer = null;
var departments = [];
var allUsers = [];
var allDevices = [];
var deviceFilter = 'all';
var editingUserId = null;
var allAuditLogs = [];
var auditFilter = 'all';
var allSessions = [];
var sessionFilter = 'all';
var allIPRules = [];
var allPolicies = [];
var sessionTimerInterval = null;

// wait for page to load
document.addEventListener('DOMContentLoaded', async function () {

  // ---- RESTORE SESSION ON PAGE LOAD ----
  var savedSession = sessionStorage.getItem('zt_session');
  if (savedSession) {
    try {
      currentUser = JSON.parse(savedSession);
      if (currentUser.role === 'Super Admin' || currentUser.role === 'Admin') {
        document.getElementById('admin-email').textContent = currentUser.email;
        document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
        showPage('admin-dashboard');
        await loadUsers();
        await loadDepartments();
        await loadDevices();
        await loadAuditLogs();
        await loadSessions();
        await loadIPRules();
        await loadPolicies();
        updateStats();
        startSessionTimer();
      } else {
        document.getElementById('user-email').textContent = currentUser.email;
        document.getElementById('user-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
        showPage('user-dashboard');
        showRiskScore();
        startSessionTimer();
      }
    } catch (e) {
      console.error('Session restore error:', e);
    }
  }

  // ---- LOGIN FORM ----
  document.getElementById('login-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var email = document.getElementById('email').value.trim();
    var password = document.getElementById('password').value;
    var errorBox = document.getElementById('login-error');
    errorBox.classList.add('hide');

    try {
      var response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
      });
      var result = await response.json();

      if (!response.ok) {
        errorBox.textContent = result.error || 'Login failed';
        errorBox.classList.remove('hide');
        return;
      }

      // save user info for OTP step
      currentUser = { userId: result.userId, email: result.email, name: result.name, role: result.role };
      document.getElementById('otp-email-display').textContent = result.email;
      showPage('otp-page');
      startOtpTimer();
    } catch (err) {
      errorBox.textContent = 'Server unavailable.';
      errorBox.classList.remove('hide');
    }
  });

  // ---- OTP INPUT BOXES ----
  var otpBoxes = document.querySelectorAll('.otp-input');

  for (var i = 0; i < otpBoxes.length; i++) {
    (function (index) {
      otpBoxes[index].addEventListener('input', function () {
        this.value = this.value.replace(/[^0-9]/g, '');
        if (this.value && index < otpBoxes.length - 1) {
          otpBoxes[index + 1].focus();
        }
        if (this.value) this.classList.add('ok');
        else this.classList.remove('ok');
      });
      otpBoxes[index].addEventListener('keydown', function (e) {
        if (e.key === 'Backspace' && !this.value && index > 0) {
          otpBoxes[index - 1].focus();
          otpBoxes[index - 1].value = '';
          otpBoxes[index - 1].classList.remove('ok');
        }
      });
    })(i);
  }

  // ---- OTP FORM SUBMIT ----
  document.getElementById('otp-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var errorBox = document.getElementById('otp-error');
    errorBox.classList.add('hide');

    var code = '';
    for (var i = 0; i < otpBoxes.length; i++) {
      code += otpBoxes[i].value;
    }

    if (code.length < 6) {
      errorBox.textContent = 'Enter all 6 digits.';
      errorBox.classList.remove('hide');
      return;
    }

    clearInterval(otpTimer);

    try {
      var response = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: currentUser.userId, code: code })
      });
      var result = await response.json();

      if (!response.ok) {
        for (var i = 0; i < otpBoxes.length; i++) {
          otpBoxes[i].classList.add('err');
          otpBoxes[i].classList.remove('ok');
        }
        errorBox.textContent = result.error || 'Verification failed.';
        errorBox.classList.remove('hide');
        setTimeout(function () {
          for (var j = 0; j < otpBoxes.length; j++) {
            otpBoxes[j].classList.remove('err');
            otpBoxes[j].value = '';
          }
          otpBoxes[0].focus();
        }, 600);
        return;
      }

      // OTP verified — update current user from server response
      currentUser = result.user;
      sessionStorage.setItem('zt_session', JSON.stringify(currentUser));

      // ---- DEVICE APPROVAL CHECK ----
      var deviceInfo = getDeviceInfo();
      var ipInfo = await fetchIPInfo();
      deviceInfo.ipAddress = ipInfo.ip;
      deviceInfo.geoLocation = ipInfo.geo;

      try {
        var devResponse = await fetch('/api/devices/request', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            userId: currentUser._id,
            userEmail: currentUser.email,
            userName: currentUser.name,
            ipAddress: deviceInfo.ipAddress,
            geoLocation: deviceInfo.geoLocation,
            deviceHealth: deviceInfo.deviceHealth,
            browser: deviceInfo.browser,
            os: deviceInfo.os,
            fingerprint: deviceInfo.fingerprint
          })
        });
        var devResult = await devResponse.json();

        if (devResult.approved === false && currentUser.role !== 'Super Admin') {
          document.getElementById('pending-ip').textContent = deviceInfo.ipAddress || '—';
          document.getElementById('pending-geo').textContent = deviceInfo.geoLocation || '—';
          document.getElementById('pending-browser').textContent = deviceInfo.browser + ' (' + deviceInfo.os + ')';
          document.getElementById('pending-health').textContent = deviceInfo.deviceHealth || '—';
          showPage('device-pending-page');
          return;
        }
      } catch (devErr) {
        console.error('Device check error:', devErr);
      }

      // show the right dashboard
      if (currentUser.role === 'Super Admin' || currentUser.role === 'Admin') {
        document.getElementById('admin-email').textContent = currentUser.email;
        document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
        showPage('admin-dashboard');
        await loadUsers();
        await loadDepartments();
        await loadDevices();
        await loadAuditLogs();
        await loadSessions();
        await loadIPRules();
        await loadPolicies();
        updateStats();
        startSessionTimer();
      } else {
        document.getElementById('user-email').textContent = currentUser.email;
        document.getElementById('user-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
        showPage('user-dashboard');
        showRiskScore();
        startSessionTimer();
      }
    } catch (err) {
      errorBox.textContent = 'Verification failed.';
      errorBox.classList.remove('hide');
    }
  });

  // ---- RESEND OTP ----
  document.getElementById('resend-btn').addEventListener('click', async function (e) {
    e.preventDefault();
    if (!currentUser || !currentUser.email) return;

    this.textContent = 'Sending...';
    try {
      await fetch('/api/auth/resend-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: currentUser.email })
      });
      this.textContent = 'Code Resent ✓';
      startOtpTimer();
    } catch (err) {
      this.textContent = 'Failed. Try again.';
    }
    var self = this;
    setTimeout(function () { self.textContent = 'Resend Code'; }, 3000);
  });

  // back to login
  document.getElementById('back-btn').addEventListener('click', function (e) {
    e.preventDefault();
    clearInterval(otpTimer);
    showPage('login-page');
  });

  // ---- LOGOUT BUTTONS ----
  document.getElementById('admin-logout').addEventListener('click', logout);
  document.getElementById('user-logout').addEventListener('click', logout);

  // ---- TAB SWITCHING ----
  var tabs = document.querySelectorAll('.tab');
  for (var t = 0; t < tabs.length; t++) {
    tabs[t].addEventListener('click', function () {
      var allTabs = document.querySelectorAll('.tab');
      for (var x = 0; x < allTabs.length; x++) allTabs[x].classList.remove('active');
      var allContent = document.querySelectorAll('.tab-content');
      for (var y = 0; y < allContent.length; y++) allContent[y].classList.remove('active');
      this.classList.add('active');
      document.getElementById(this.dataset.tab).classList.add('active');
    });
  }

  // ---- CREATE USER FORM ----
  document.getElementById('create-user-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var name = document.getElementById('new-name').value.trim();
    var email = document.getElementById('new-email').value.trim();
    var password = document.getElementById('new-password').value;
    var role = document.getElementById('new-role').value;
    var dept = document.getElementById('new-dept').value;

    try {
      var response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, email: email, password: password, role: role, department: dept })
      });

      if (!response.ok) {
        var err = await response.json();
        alert(err.error || 'Failed');
        return;
      }

      await loadUsers();
      updateStats();
      closeModal('create-user-modal');
      document.getElementById('create-user-form').reset();
    } catch (err) {
      alert('Failed to create user');
    }
  });

  // ---- EDIT USER FORM ----
  document.getElementById('edit-user-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var name = document.getElementById('edit-name').value.trim();
    var email = document.getElementById('edit-email').value.trim();
    var role = document.getElementById('edit-role-select').value;
    var dept = document.getElementById('edit-dept-select').value;
    var status = document.getElementById('edit-status-select').value;
    var mfa = document.getElementById('edit-mfa').checked;

    try {
      var response = await fetch('/api/users/' + editingUserId, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, email: email, role: role, department: dept, status: status, mfa: mfa })
      });

      if (!response.ok) {
        var err = await response.json();
        alert(err.error || 'Failed');
        return;
      }

      await loadUsers();
      updateStats();
      closeModal('edit-user-modal');
    } catch (err) {
      alert('Failed to update user');
    }
  });

  // ---- CLOSE MODAL ON OVERLAY CLICK ----
  var overlays = document.querySelectorAll('.modal-overlay');
  for (var o = 0; o < overlays.length; o++) {
    overlays[o].addEventListener('click', function (e) {
      if (e.target === this) {
        this.classList.add('hide');
      }
    });
  }

  // ---- PROFILE FORM ----
  document.getElementById('profile-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msgBox = document.getElementById('profile-msg');
    msgBox.classList.add('hide');

    var name = document.getElementById('profile-name').value.trim();
    var phone = document.getElementById('profile-phone').value.trim();
    var gender = document.getElementById('profile-gender').value;

    try {
      var response = await fetch('/api/auth/profile/' + currentUser._id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, phone: phone, gender: gender })
      });
      var result = await response.json();

      if (!response.ok) {
        msgBox.textContent = result.error || 'Failed to update';
        msgBox.className = 'profile-msg err';
        return;
      }

      currentUser.name = result.user.name;
      currentUser.phone = result.user.phone;
      currentUser.gender = result.user.gender;
      sessionStorage.setItem('zt_session', JSON.stringify(currentUser));
      document.getElementById('profile-display-name').textContent = currentUser.name;
      document.getElementById('profile-avatar-letter').textContent = currentUser.name.charAt(0).toUpperCase();

      if (currentUser.role === 'Super Admin' || currentUser.role === 'Admin') {
        document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
      } else {
        document.getElementById('user-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
      }

      msgBox.textContent = 'Profile updated ✓';
      msgBox.className = 'profile-msg success';
    } catch (err) {
      msgBox.textContent = 'Server error';
      msgBox.className = 'profile-msg err';
    }
  });

  // ---- PASSWORD FORM ----
  document.getElementById('password-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msgBox = document.getElementById('pw-msg');
    msgBox.classList.add('hide');

    var current = document.getElementById('pw-current').value;
    var newPw = document.getElementById('pw-new').value;

    if (newPw.length < 6) {
      msgBox.textContent = 'Password must be at least 6 characters';
      msgBox.className = 'profile-msg err';
      return;
    }

    try {
      var response = await fetch('/api/auth/profile/' + currentUser._id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: current, newPassword: newPw })
      });
      var result = await response.json();

      if (!response.ok) {
        msgBox.textContent = result.error || 'Failed';
        msgBox.className = 'profile-msg err';
        return;
      }

      msgBox.textContent = 'Password updated ✓';
      msgBox.className = 'profile-msg success';
      document.getElementById('password-form').reset();
    } catch (err) {
      msgBox.textContent = 'Server error';
      msgBox.className = 'profile-msg err';
    }
  });

}); // end DOMContentLoaded

// ========== HELPER FUNCTIONS ==========

function showPage(id) {
  var pages = document.querySelectorAll('.page');
  for (var i = 0; i < pages.length; i++) pages[i].classList.remove('active');
  document.getElementById(id).classList.add('active');
}

function openModal(id) {
  document.getElementById(id).classList.remove('hide');
}

function closeModal(id) {
  document.getElementById(id).classList.add('hide');
}

function logout() {
  currentUser = null;
  clearInterval(sessionTimerInterval);
  sessionStorage.removeItem('zt_session');
  showPage('login-page');
  document.getElementById('login-form').reset();
}

function switchToTab(tabId) {
  var allTabs = document.querySelectorAll('.tab');
  for (var x = 0; x < allTabs.length; x++) allTabs[x].classList.remove('active');
  var allContent = document.querySelectorAll('.tab-content');
  for (var y = 0; y < allContent.length; y++) allContent[y].classList.remove('active');

  var btn = document.querySelector('.tab[data-tab="' + tabId + '"]');
  if (btn) btn.classList.add('active');
  document.getElementById(tabId).classList.add('active');
}

function startOtpTimer() {
  var secs = 60;
  document.getElementById('otp-timer').textContent = secs;
  clearInterval(otpTimer);
  otpTimer = setInterval(function () {
    secs--;
    document.getElementById('otp-timer').textContent = secs;
    if (secs <= 0) clearInterval(otpTimer);
  }, 1000);
}

function formatDate(d) {
  if (!d) return '—';
  var dt = new Date(d);
  return dt.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) + ' ' + dt.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

// ========== DEVICE INFO ==========
function getDeviceInfo() {
  var ua = navigator.userAgent;
  var browser = 'Unknown';
  var os = 'Unknown';

  if (ua.indexOf('Chrome') > -1 && ua.indexOf('Edg') === -1) browser = 'Chrome';
  else if (ua.indexOf('Firefox') > -1) browser = 'Firefox';
  else if (ua.indexOf('Safari') > -1 && ua.indexOf('Chrome') === -1) browser = 'Safari';
  else if (ua.indexOf('Edg') > -1) browser = 'Edge';

  if (ua.indexOf('Windows') > -1) os = 'Windows';
  else if (ua.indexOf('Mac') > -1) os = 'macOS';
  else if (ua.indexOf('Linux') > -1) os = 'Linux';
  else if (ua.indexOf('Android') > -1) os = 'Android';
  else if (ua.indexOf('iPhone') > -1 || ua.indexOf('iPad') > -1) os = 'iOS';

  var isSecure = location.protocol === 'https:';
  var hasCookies = navigator.cookieEnabled;
  var health = 'Good';
  if (!isSecure) health = 'Poor — Not HTTPS';
  else if (!hasCookies) health = 'Fair — Cookies disabled';

  var fingerprint = btoa(ua + screen.width + screen.height + navigator.language + (new Date()).getTimezoneOffset()).substring(0, 32);

  return {
    browser: browser + ' (' + os + ')',
    os: os,
    deviceHealth: health,
    fingerprint: fingerprint,
    ipAddress: '',
    geoLocation: ''
  };
}

async function fetchIPInfo() {
  try {
    var r = await fetch('https://ipapi.co/json/');
    var d = await r.json();
    return { ip: d.ip || '', geo: (d.city || '') + ', ' + (d.region || '') + ', ' + (d.country_name || '') };
  } catch (e) {
    return { ip: '', geo: '' };
  }
}

// ========== DATA LOADING ==========
async function loadUsers() {
  try {
    var r = await fetch('/api/users');
    allUsers = await r.json();
    renderUsersTable();
  } catch (e) { console.error('Load users failed:', e); }
}

function renderUsersTable() {
  var tbody = document.getElementById('users-table-body');
  if (!tbody) return;
  if (!allUsers.length) { tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#94a3b8">No users found</td></tr>'; return; }

  var html = '';
  for (var i = 0; i < allUsers.length; i++) {
    var u = allUsers[i];
    var statusClass = u.status === 'Active' ? 'green-bg' : 'red-bg';
    var mfaBadge = u.mfa ? '<span class="badge green-bg">On</span>' : '<span class="badge red-bg">Off</span>';
    html += '<tr>'
      + '<td><strong>' + u.name + '</strong></td>'
      + '<td>' + u.email + '</td>'
      + '<td><span class="badge blue-bg">' + u.role + '</span></td>'
      + '<td>' + (u.department || '—') + '</td>'
      + '<td><span class="badge ' + statusClass + '">' + u.status + '</span></td>'
      + '<td>' + mfaBadge + '</td>'
      + '<td class="td-actions">'
      + '<button class="tbl-btn" onclick="editUser(\'' + u._id + '\')"><i class="fas fa-pen"></i></button>'
      + '<button class="tbl-btn danger" onclick="deleteUser(\'' + u._id + '\')"><i class="fas fa-trash"></i></button>'
      + '</td></tr>';
  }
  tbody.innerHTML = html;
}

function editUser(id) {
  var u = allUsers.find(function (x) { return x._id === id; });
  if (!u) return;
  editingUserId = id;
  document.getElementById('edit-name').value = u.name;
  document.getElementById('edit-email').value = u.email;
  document.getElementById('edit-role-select').value = u.role;
  document.getElementById('edit-status-select').value = u.status;
  document.getElementById('edit-mfa').checked = u.mfa;

  var deptSel = document.getElementById('edit-dept-select');
  deptSel.innerHTML = '';
  for (var i = 0; i < departments.length; i++) {
    deptSel.innerHTML += '<option value="' + departments[i].name + '"' + (departments[i].name === u.department ? ' selected' : '') + '>' + departments[i].name + '</option>';
  }
  openModal('edit-user-modal');
}

async function deleteUser(id) {
  if (!confirm('Delete this user?')) return;
  try {
    await fetch('/api/users/' + id, { method: 'DELETE' });
    await loadUsers();
    updateStats();
  } catch (e) { alert('Failed to delete user'); }
}

// ---- Departments ----
async function loadDepartments() {
  try {
    var r = await fetch('/api/departments');
    departments = await r.json();
    renderDeptList();
    populateDeptDropdowns();
  } catch (e) { console.error('Load departments failed:', e); }
}

function renderDeptList() {
  var list = document.getElementById('dept-list');
  if (!list) return;
  list.innerHTML = '';
  for (var i = 0; i < departments.length; i++) {
    list.innerHTML += '<li>' + departments[i].name + '<button class="tbl-btn danger" style="margin-left:auto" onclick="deleteDepartment(\'' + departments[i]._id + '\')"><i class="fas fa-trash"></i></button></li>';
  }
}

function populateDeptDropdowns() {
  var dd = [document.getElementById('new-dept')];
  for (var d = 0; d < dd.length; d++) {
    if (!dd[d]) continue;
    dd[d].innerHTML = '';
    for (var i = 0; i < departments.length; i++) {
      dd[d].innerHTML += '<option value="' + departments[i].name + '">' + departments[i].name + '</option>';
    }
  }
}

async function addDepartment() {
  var name = document.getElementById('new-dept-name').value.trim();
  if (!name) return;
  try {
    var r = await fetch('/api/departments', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name }) });
    if (!r.ok) { var e = await r.json(); alert(e.error); return; }
    document.getElementById('new-dept-name').value = '';
    await loadDepartments();
  } catch (e) { alert('Failed'); }
}

async function deleteDepartment(id) {
  if (!confirm('Delete this department?')) return;
  try {
    await fetch('/api/departments/' + id, { method: 'DELETE' });
    await loadDepartments();
  } catch (e) { alert('Failed'); }
}

// ---- Devices ----
async function loadDevices() {
  try {
    var r = await fetch('/api/devices');
    allDevices = await r.json();
    renderDevicesTable();
    updateDeviceStats();
  } catch (e) { console.error('Load devices failed:', e); }
}

function renderDevicesTable() {
  var tbody = document.getElementById('devices-table-body');
  if (!tbody) return;

  var filtered = allDevices;
  if (deviceFilter !== 'all') {
    filtered = allDevices.filter(function (d) { return d.status === deviceFilter; });
  }

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:#94a3b8">No device requests found</td></tr>';
    return;
  }

  var html = '';
  for (var i = 0; i < filtered.length; i++) {
    var d = filtered[i];
    var statusClass = d.status === 'Approved' ? 'green-bg' : d.status === 'Rejected' ? 'red-bg' : 'orange-bg';
    var healthClass = (d.device_health || '').indexOf('Poor') > -1 ? 'red-bg' : (d.device_health || '').indexOf('Fair') > -1 ? 'orange-bg' : 'green-bg';
    var actions = '';
    if (d.status === 'Pending') {
      actions = '<button class="tbl-btn success" onclick="approveDevice(\'' + d.id + '\')"><i class="fas fa-check"></i></button>'
        + '<button class="tbl-btn danger" onclick="rejectDevice(\'' + d.id + '\')"><i class="fas fa-times"></i></button>';
    }
    actions += '<button class="tbl-btn danger" onclick="deleteDevice(\'' + d.id + '\')"><i class="fas fa-trash"></i></button>';

    html += '<tr>'
      + '<td><strong>' + (d.user_name || '—') + '</strong><br><small style="color:#94a3b8">' + (d.user_email || '') + '</small></td>'
      + '<td><code>' + (d.ip_address || '—') + '</code></td>'
      + '<td>' + (d.geo_location || '—') + '</td>'
      + '<td><span class="badge ' + healthClass + '">' + (d.device_health || '—') + '</span></td>'
      + '<td>' + (d.browser || '—') + '</td>'
      + '<td><span class="badge ' + statusClass + '">' + d.status + '</span></td>'
      + '<td>' + (d.approved_by || '—') + '</td>'
      + '<td>' + formatDate(d.created_at) + '</td>'
      + '<td class="td-actions">' + actions + '</td>'
      + '</tr>';
  }
  tbody.innerHTML = html;
}

function updateDeviceStats() {
  var pending = 0;
  for (var i = 0; i < allDevices.length; i++) {
    if (allDevices[i].status === 'Pending') pending++;
  }
  var el = document.getElementById('stat-pending-devices');
  if (el) el.textContent = pending;
}

function filterDevices(status) {
  deviceFilter = status;
  renderDevicesTable();
  var btns = document.querySelectorAll('#tab-devices .filter-btn');
  for (var i = 0; i < btns.length; i++) btns[i].classList.remove('active');
  event.target.classList.add('active');
}

async function approveDevice(deviceId) {
  if (!confirm('Approve this device?')) return;
  try {
    await fetch('/api/devices/' + deviceId + '/approve', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ approvedBy: currentUser.email }) });
    await loadDevices();
  } catch (e) { alert('Failed'); }
}

async function rejectDevice(deviceId) {
  if (!confirm('Reject this device?')) return;
  try {
    await fetch('/api/devices/' + deviceId + '/reject', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ approvedBy: currentUser.email }) });
    await loadDevices();
  } catch (e) { alert('Failed'); }
}

async function deleteDevice(deviceId) {
  if (!confirm('Delete this device record?')) return;
  try {
    await fetch('/api/devices/' + deviceId, { method: 'DELETE' });
    await loadDevices();
  } catch (e) { alert('Failed'); }
}

async function checkDeviceApproval() {
  if (!currentUser) return;
  var deviceInfo = getDeviceInfo();
  try {
    var r = await fetch('/api/devices/check/' + currentUser._id + '/' + deviceInfo.fingerprint);
    var result = await r.json();
    var msgBox = document.getElementById('device-pending-msg');

    if (result.approved) {
      msgBox.textContent = 'Device approved! Redirecting...';
      msgBox.className = 'profile-msg success';

      setTimeout(function () {
        if (currentUser.role === 'Super Admin' || currentUser.role === 'Admin') {
          document.getElementById('admin-email').textContent = currentUser.email;
          document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
          showPage('admin-dashboard');
          loadUsers(); loadDepartments(); loadDevices(); loadAuditLogs(); loadSessions(); loadIPRules(); loadPolicies();
          updateStats();
          startSessionTimer();
        } else {
          document.getElementById('user-email').textContent = currentUser.email;
          document.getElementById('user-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
          showPage('user-dashboard');
          showRiskScore();
          startSessionTimer();
        }
      }, 1000);
    } else {
      msgBox.textContent = 'Device is still pending approval. Please wait.';
      msgBox.className = 'profile-msg err';
    }
  } catch (e) {
    console.error('Check device error:', e);
  }
}

// ========== AUDIT LOGS ==========
async function loadAuditLogs() {
  try {
    var r = await fetch('/api/audit');
    allAuditLogs = await r.json();
    renderAuditTable();
    updateAuditStats();
  } catch (e) { console.error('Load audit logs failed:', e); }
}

function renderAuditTable() {
  var tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  var filtered = allAuditLogs;
  if (auditFilter !== 'all') {
    filtered = allAuditLogs.filter(function (a) { return a.severity === auditFilter; });
  }

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#94a3b8">No audit logs found</td></tr>';
    return;
  }

  var html = '';
  for (var i = 0; i < filtered.length; i++) {
    var a = filtered[i];
    var sevClass = a.severity === 'critical' ? 'red-bg' : a.severity === 'warning' ? 'orange-bg' : 'blue-bg';
    var sevIcon = a.severity === 'critical' ? 'fa-circle-exclamation' : a.severity === 'warning' ? 'fa-triangle-exclamation' : 'fa-circle-info';
    var eventLabel = (a.event_type || '').replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });

    html += '<tr>'
      + '<td><span class="badge ' + sevClass + '"><i class="fas ' + sevIcon + '"></i> ' + a.severity + '</span></td>'
      + '<td><strong>' + eventLabel + '</strong></td>'
      + '<td>' + (a.user_email || '—') + '</td>'
      + '<td><code>' + (a.ip_address || '—') + '</code></td>'
      + '<td>' + (a.details || '—') + '</td>'
      + '<td>' + formatDate(a.created_at) + '</td>'
      + '</tr>';
  }
  tbody.innerHTML = html;
}

function filterAudit(severity) {
  auditFilter = severity;
  renderAuditTable();
  var btns = document.querySelectorAll('#tab-audit .filter-btn');
  for (var i = 0; i < btns.length; i++) btns[i].classList.remove('active');
  event.target.classList.add('active');
}

function updateAuditStats() {
  var warnings = 0;
  var critical = 0;
  var now = Date.now();
  for (var i = 0; i < allAuditLogs.length; i++) {
    var age = now - new Date(allAuditLogs[i].created_at).getTime();
    if (age < 24 * 60 * 60 * 1000) {
      if (allAuditLogs[i].severity === 'warning') warnings++;
      if (allAuditLogs[i].severity === 'critical') critical++;
    }
  }
  var wEl = document.getElementById('stat-audit-warnings');
  var cEl = document.getElementById('stat-audit-critical');
  if (wEl) wEl.textContent = warnings;
  if (cEl) cEl.textContent = critical;
}

// ========== SESSIONS ==========
async function loadSessions() {
  try {
    var r = await fetch('/api/sessions');
    allSessions = await r.json();
    renderSessionsTable();
    updateSessionStats();
  } catch (e) { console.error('Load sessions failed:', e); }
}

function renderSessionsTable() {
  var tbody = document.getElementById('sessions-table-body');
  if (!tbody) return;

  var filtered = allSessions;
  if (sessionFilter === 'active') {
    filtered = allSessions.filter(function (s) { return s.is_active && new Date(s.expires_at) > new Date(); });
  } else if (sessionFilter === 'expired') {
    filtered = allSessions.filter(function (s) { return !s.is_active || new Date(s.expires_at) <= new Date(); });
  }

  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#94a3b8">No sessions found</td></tr>';
    return;
  }

  var html = '';
  for (var i = 0; i < filtered.length; i++) {
    var s = filtered[i];
    var isActive = s.is_active && new Date(s.expires_at) > new Date();
    var statusBadge = isActive ? '<span class="badge green-bg"><i class="fas fa-circle"></i> Active</span>' : '<span class="badge red-bg">Expired</span>';

    if (s.revoked_by) statusBadge = '<span class="badge red-bg"><i class="fas fa-ban"></i> Revoked</span>';

    var actions = '';
    if (isActive) {
      actions = '<button class="tbl-btn danger" onclick="revokeSession(\'' + s.id + '\')"><i class="fas fa-ban"></i> Revoke</button>';
    }

    html += '<tr>'
      + '<td><strong>' + (s.user_name || '—') + '</strong><br><small style="color:#94a3b8">' + (s.user_email || '') + '</small></td>'
      + '<td><code>' + (s.ip_address || '—') + '</code></td>'
      + '<td>' + (s.geo_location || '—') + '</td>'
      + '<td>' + (s.browser || '—') + '</td>'
      + '<td>' + formatDate(s.created_at) + '</td>'
      + '<td>' + formatDate(s.expires_at) + '</td>'
      + '<td>' + statusBadge + '</td>'
      + '<td class="td-actions">' + actions + '</td>'
      + '</tr>';
  }
  tbody.innerHTML = html;
}

function filterSessions(status) {
  sessionFilter = status;
  renderSessionsTable();
  var btns = document.querySelectorAll('#tab-sessions .filter-btn');
  for (var i = 0; i < btns.length; i++) btns[i].classList.remove('active');
  event.target.classList.add('active');
}

function updateSessionStats() {
  var active = 0;
  for (var i = 0; i < allSessions.length; i++) {
    if (allSessions[i].is_active && new Date(allSessions[i].expires_at) > new Date()) active++;
  }
  var el = document.getElementById('stat-active-sessions');
  if (el) el.textContent = active;
}

async function revokeSession(sessionId) {
  if (!confirm('Revoke this session?')) return;
  try {
    await fetch('/api/sessions/' + sessionId + '/revoke', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ revokedBy: currentUser.email })
    });
    await loadSessions();
  } catch (e) { alert('Failed'); }
}

// ========== IP RULES ==========
async function loadIPRules() {
  try {
    var r = await fetch('/api/ip-rules');
    allIPRules = await r.json();
    renderIPRules();
  } catch (e) { console.error('Load IP rules failed:', e); }
}

function renderIPRules() {
  var allowList = document.getElementById('allow-ip-list');
  var blockList = document.getElementById('block-ip-list');
  if (!allowList || !blockList) return;

  var allowHTML = '';
  var blockHTML = '';

  for (var i = 0; i < allIPRules.length; i++) {
    var rule = allIPRules[i];
    var item = '<li><i class="fas ' + (rule.rule_type === 'allow' ? 'fa-shield-check green-text' : 'fa-ban red-text') + '"></i> '
      + '<code>' + rule.ip_pattern + '</code>'
      + (rule.label ? ' <small style="color:#94a3b8">' + rule.label + '</small>' : '')
      + '<button class="tbl-btn danger" style="margin-left:auto" onclick="deleteIPRule(\'' + rule.id + '\')"><i class="fas fa-trash"></i></button>'
      + '</li>';

    if (rule.rule_type === 'allow') allowHTML += item;
    else blockHTML += item;
  }

  allowList.innerHTML = allowHTML || '<li style="color:#94a3b8">No allowlist rules</li>';
  blockList.innerHTML = blockHTML || '<li style="color:#94a3b8">No blocklist rules</li>';
}

async function addIPRule(type) {
  var ipInput = document.getElementById(type + '-ip-input');
  var labelInput = document.getElementById(type + '-ip-label');
  var ip = ipInput.value.trim();
  var label = labelInput.value.trim();

  if (!ip) { alert('Enter an IP address or pattern'); return; }

  try {
    var r = await fetch('/api/ip-rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip_pattern: ip, rule_type: type, label: label, created_by: currentUser.email })
    });
    if (!r.ok) { var e = await r.json(); alert(e.error); return; }
    ipInput.value = '';
    labelInput.value = '';
    await loadIPRules();
  } catch (e) { alert('Failed'); }
}

async function deleteIPRule(id) {
  if (!confirm('Delete this IP rule?')) return;
  try {
    await fetch('/api/ip-rules/' + id, { method: 'DELETE' });
    await loadIPRules();
  } catch (e) { alert('Failed'); }
}

// ========== SECURITY POLICIES ==========
async function loadPolicies() {
  try {
    var r = await fetch('/api/policies');
    allPolicies = await r.json();
    renderPolicies();
  } catch (e) { console.error('Load policies failed:', e); }
}

function renderPolicies() {
  var panel = document.getElementById('policies-panel');
  if (!panel) return;

  var policyConfig = {
    'session_timeout_minutes': { icon: 'fa-clock', label: 'Session Timeout (min)', type: 'number' },
    'max_failed_logins': { icon: 'fa-lock', label: 'Max Failed Logins', type: 'number' },
    'mfa_required': { icon: 'fa-shield-halved', label: 'MFA Required', type: 'toggle' },
    'password_min_length': { icon: 'fa-key', label: 'Min Password Length', type: 'number' },
    'device_approval_required': { icon: 'fa-laptop-medical', label: 'Device Approval Required', type: 'toggle' },
    'ip_restriction_enabled': { icon: 'fa-globe', label: 'IP Restriction Enabled', type: 'toggle' }
  };

  var html = '';
  for (var i = 0; i < allPolicies.length; i++) {
    var p = allPolicies[i];
    var cfg = policyConfig[p.policy_key] || { icon: 'fa-cog', label: p.policy_key, type: 'text' };

    if (cfg.type === 'toggle') {
      var isOn = p.policy_value === 'true';
      html += '<div class="policy-item">'
        + '<div class="policy-info"><i class="fas ' + cfg.icon + ' blue-text"></i> <span>' + cfg.label + '</span></div>'
        + '<label class="toggle-switch"><input type="checkbox" ' + (isOn ? 'checked' : '') + ' onchange="updatePolicy(\'' + p.policy_key + '\', this.checked ? \'true\' : \'false\')"><span class="toggle-slider"></span></label>'
        + '</div>';
    } else {
      html += '<div class="policy-item">'
        + '<div class="policy-info"><i class="fas ' + cfg.icon + ' blue-text"></i> <span>' + cfg.label + '</span></div>'
        + '<input type="number" class="policy-input" value="' + p.policy_value + '" onchange="updatePolicy(\'' + p.policy_key + '\', this.value)" min="1" max="999">'
        + '</div>';
    }
  }

  panel.innerHTML = html || '<p class="muted">No policies found. Run migrate_features.sql in Supabase.</p>';
}

async function updatePolicy(key, value) {
  try {
    var r = await fetch('/api/policies/' + key, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: value, updatedBy: currentUser.email })
    });
    if (!r.ok) { var e = await r.json(); alert(e.error); return; }
    await loadPolicies();
  } catch (e) { alert('Failed to update policy'); }
}

// ========== RISK SCORE DISPLAY ==========
function showRiskScore() {
  if (!currentUser || !currentUser.riskScore) return;

  var score = currentUser.riskScore;
  var el = document.getElementById('risk-score-number');
  var gauge = document.getElementById('risk-gauge-fill');
  var factorsList = document.getElementById('risk-factors-list');

  if (el) el.textContent = score;
  if (gauge) {
    gauge.style.width = score + '%';
    gauge.className = 'risk-gauge-fill';
    if (score >= 70) gauge.classList.add('good');
    else if (score >= 40) gauge.classList.add('medium');
    else gauge.classList.add('bad');
  }

  if (factorsList && currentUser.riskFactors) {
    var html = '';
    for (var i = 0; i < currentUser.riskFactors.length; i++) {
      var f = currentUser.riskFactors[i];
      var icon = f.impact === 0 ? 'fa-circle-check green-text' : 'fa-circle-minus red-text';
      html += '<div class="risk-factor"><i class="fas ' + icon + '"></i> ' + f.factor + ': ' + f.detail + '</div>';
    }
    factorsList.innerHTML = html;
  }
}

// ========== SESSION TIMER ==========
function startSessionTimer() {
  if (!currentUser || !currentUser.sessionExpiresAt) return;

  var timerPill = document.getElementById(currentUser.role === 'Super Admin' || currentUser.role === 'Admin' ? 'session-timer-pill' : 'user-session-timer-pill');
  var timerText = document.getElementById(currentUser.role === 'Super Admin' || currentUser.role === 'Admin' ? 'session-timer-text' : 'user-session-timer-text');

  if (!timerPill || !timerText) return;
  timerPill.classList.remove('hide');

  clearInterval(sessionTimerInterval);
  sessionTimerInterval = setInterval(function () {
    var remaining = new Date(currentUser.sessionExpiresAt).getTime() - Date.now();

    if (remaining <= 0) {
      clearInterval(sessionTimerInterval);
      timerText.textContent = 'EXPIRED';
      timerPill.classList.add('expired');
      alert('Session expired. Please log in again.');
      logout();
      return;
    }

    var mins = Math.floor(remaining / 60000);
    var secs = Math.floor((remaining % 60000) / 1000);
    timerText.textContent = String(mins).padStart(2, '0') + ':' + String(secs).padStart(2, '0');

    // warning at 5 minutes
    if (remaining < 5 * 60 * 1000) {
      timerPill.classList.add('warning');
    }
  }, 1000);
}

// ========== STATS UPDATE ==========
function updateStats() {
  var el = document.getElementById('stat-total-users');
  if (el) el.textContent = allUsers.length;
  updateDeviceStats();
  updateAuditStats();
  updateSessionStats();
}

// ========== PROFILE MODAL ==========
function openProfileModal() {
  if (!currentUser) return;

  document.getElementById('profile-display-name').textContent = currentUser.name;
  document.getElementById('profile-display-role').textContent = currentUser.role + ' • ' + (currentUser.department || 'General');
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
