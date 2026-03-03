// global variables
var currentUser = null;
var otpTimer = null;
var departments = [];
var allUsers = [];
var allDevices = [];
var deviceFilter = 'all';
var editingUserId = null;

// wait for page to load
document.addEventListener('DOMContentLoaded', function () {

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
      var data = await response.json();

      if (!response.ok) {
        errorBox.textContent = data.error;
        errorBox.classList.remove('hide');
        return;
      }

      // save user info and show OTP page
      currentUser = { userId: data.userId, name: data.name, role: data.role, email: email };
      document.getElementById('otp-email-display').textContent = email;
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
        // only allow numbers
        this.value = this.value.replace(/[^0-9]/g, '');
        // move to next box
        if (this.value && index < 5) {
          otpBoxes[index + 1].focus();
        }
        // show green border if filled
        if (this.value) {
          this.classList.add('ok');
        } else {
          this.classList.remove('ok');
        }
      });

      otpBoxes[index].addEventListener('keydown', function (e) {
        // move back on backspace
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

    // collect all 6 digits
    var code = '';
    for (var i = 0; i < otpBoxes.length; i++) {
      code = code + otpBoxes[i].value;
    }

    // check if all digits entered
    if (code.length < 6) {
      errorBox.textContent = 'Enter all 6 digits.';
      errorBox.classList.remove('hide');
      return;
    }

    clearInterval(otpTimer);

    // verify with backend
    try {
      var response = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: currentUser.userId, code: code })
      });
      var data = await response.json();

      if (!response.ok) {
        errorBox.textContent = data.error || 'Verification failed';
        errorBox.classList.remove('hide');
        // shake the boxes and clear them
        for (var j = 0; j < otpBoxes.length; j++) {
          otpBoxes[j].classList.add('err');
          otpBoxes[j].value = '';
        }
        setTimeout(function () {
          for (var k = 0; k < otpBoxes.length; k++) {
            otpBoxes[k].classList.remove('err');
          }
        }, 400);
        otpBoxes[0].focus();
        startOtpTimer();
        return;
      }

      if (!response.ok) {
        errorBox.textContent = data.error;
        errorBox.classList.remove('hide');
        return;
      }

      currentUser = data.user;

      // ---- DEVICE APPROVAL CHECK ----
      var deviceInfo = getDeviceInfo();

      // fetch real IP and geo location
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
        var devData = await devResponse.json();

        // Super Admin bypasses device approval
        if (currentUser.role === 'Super Admin') {
          // auto-approve for super admin
        } else if (!devData.approved) {
          // device not approved — show pending page
          document.getElementById('pending-ip').textContent = deviceInfo.ipAddress || '—';
          document.getElementById('pending-geo').textContent = deviceInfo.geoLocation || '—';
          document.getElementById('pending-browser').textContent = deviceInfo.browser || '—';
          document.getElementById('pending-health').textContent = deviceInfo.deviceHealth || '—';
          showPage('device-pending-page');
          return;
        }
      } catch (devErr) {
        console.error('Device check error:', devErr);
        // if device check fails, continue anyway (graceful degradation)
      }

      // show the right dashboard based on role
      if (currentUser.role === 'Super Admin' || currentUser.role === 'Admin') {
        document.getElementById('admin-email').textContent = currentUser.email;
        document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
        await loadUsers();
        await loadDepartments();
        await loadDevices();
        updateStats();
        showPage('admin-dashboard');
      } else {
        document.getElementById('user-email').textContent = currentUser.email;
        document.getElementById('user-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
        showPage('user-dashboard');
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
    this.style.pointerEvents = 'none';

    try {
      var response = await fetch('/api/auth/resend-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: currentUser.email })
      });
      var data = await response.json();

      if (response.ok) {
        startOtpTimer();
        document.getElementById('otp-error').classList.add('hide');
      } else {
        var errorBox = document.getElementById('otp-error');
        errorBox.textContent = data.error || 'Failed to resend';
        errorBox.classList.remove('hide');
      }
    } catch (err) {
      var errorBox2 = document.getElementById('otp-error');
      errorBox2.textContent = 'Failed to resend OTP';
      errorBox2.classList.remove('hide');
    }

    this.textContent = 'Resend Code';
    this.style.pointerEvents = 'auto';
  });

  // ---- BACK TO LOGIN ----
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
      // remove active from all tabs
      var allTabs = document.querySelectorAll('.tab');
      var allContent = document.querySelectorAll('.tab-content');
      for (var x = 0; x < allTabs.length; x++) {
        allTabs[x].classList.remove('active');
      }
      for (var y = 0; y < allContent.length; y++) {
        allContent[y].classList.remove('active');
      }
      // activate clicked tab
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
    var department = document.getElementById('new-dept').value;

    if (!name || !email || !password) return;

    try {
      var response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name,
          email: email,
          password: password,
          role: role,
          department: department
        })
      });
      var data = await response.json();

      if (!response.ok) {
        alert(data.error);
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
    var department = document.getElementById('edit-dept-select').value;
    var status = document.getElementById('edit-status-select').value;
    var mfa = document.getElementById('edit-mfa').checked;

    if (!name || !email) {
      alert('Name and email are required');
      return;
    }

    try {
      var response = await fetch('/api/users/' + editingUserId, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name,
          email: email,
          role: role,
          department: department,
          status: status,
          mfa: mfa
        })
      });
      var data = await response.json();

      if (!response.ok) {
        alert(data.error || 'Failed to update user');
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
  for (var m = 0; m < overlays.length; m++) {
    overlays[m].addEventListener('click', function (e) {
      if (e.target === this) {
        this.classList.add('hide');
      }
    });
  }
});


// ========== HELPER FUNCTIONS ==========

// show a page by id
function showPage(pageId) {
  var pages = document.querySelectorAll('.page');
  for (var i = 0; i < pages.length; i++) {
    pages[i].classList.remove('active');
  }
  document.getElementById(pageId).classList.add('active');
}

// start 60 second OTP countdown
function startOtpTimer() {
  var seconds = 60;
  var timerDisplay = document.getElementById('otp-timer');
  timerDisplay.textContent = seconds;

  if (otpTimer) clearInterval(otpTimer);

  // clear and reset OTP input boxes
  var boxes = document.querySelectorAll('.otp-input');
  for (var i = 0; i < boxes.length; i++) {
    boxes[i].value = '';
    boxes[i].className = 'otp-input';
  }
  boxes[0].focus();

  otpTimer = setInterval(function () {
    seconds--;
    timerDisplay.textContent = seconds;
    if (seconds <= 0) {
      clearInterval(otpTimer);
      var errorBox = document.getElementById('otp-error');
      errorBox.textContent = 'OTP expired. Click Resend Code.';
      errorBox.classList.remove('hide');
    }
  }, 1000);
}

// logout and go back to login
function logout() {
  clearInterval(otpTimer);
  currentUser = null;
  otp = null;
  document.getElementById('email').value = '';
  document.getElementById('password').value = '';
  document.getElementById('login-error').classList.add('hide');

  // reset tabs to home
  var tabs = document.querySelectorAll('.tab');
  var contents = document.querySelectorAll('.tab-content');
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.remove('active');
  }
  for (var j = 0; j < contents.length; j++) {
    contents[j].classList.remove('active');
  }
  document.querySelector('.tab[data-tab="tab-home"]').classList.add('active');
  document.getElementById('tab-home').classList.add('active');

  showPage('login-page');
}


// ========== DATA LOADING ==========

// load all users from the server
async function loadUsers() {
  try {
    var response = await fetch('/api/users');
    allUsers = await response.json();
    renderUsersTable();
  } catch (err) {
    console.error('Failed to load users', err);
  }
}

// load all departments from the server
async function loadDepartments() {
  try {
    var response = await fetch('/api/departments');
    departments = await response.json();
    fillDepartmentDropdowns();
    renderDepartmentList();
  } catch (err) {
    console.error('Failed to load departments', err);
  }
}


// ========== RENDERING ==========

// draw the users table
function renderUsersTable() {
  var tbody = document.getElementById('users-table-body');
  var html = '';

  for (var i = 0; i < allUsers.length; i++) {
    var user = allUsers[i];

    // pick badge color based on role
    var roleBadge = 'blue-bg';
    if (user.role === 'Admin') roleBadge = 'purple-bg';
    if (user.role === 'Manager') roleBadge = 'orange-bg';

    // pick status badge color
    var statusBadge = user.status === 'Active' ? 'green-bg' : 'red-bg';

    // mfa badge
    var mfaBadge = user.mfa ? '<span class="badge green-bg">On</span>' : '<span class="badge red-bg">Off</span>';

    html += '<tr>';
    html += '<td>' + user.name + '</td>';
    html += '<td>' + user.email + '</td>';
    html += '<td><span class="badge ' + roleBadge + '">' + user.role + '</span></td>';
    html += '<td>' + user.department + '</td>';
    html += '<td><span class="badge ' + statusBadge + '">' + user.status + '</span></td>';
    html += '<td>' + mfaBadge + '</td>';
    html += '<td class="td-actions">';
    html += '<button class="tbl-btn" onclick="openEditUser(\'' + user._id + '\')" title="Edit User"><i class="fas fa-pen"></i></button>';
    html += '<button class="tbl-btn danger" onclick="removeUser(\'' + user._id + '\')" title="Delete User"><i class="fas fa-trash"></i></button>';
    html += '</td>';
    html += '</tr>';
  }

  tbody.innerHTML = html;
}

// update the total users count on dashboard
function updateStats() {
  var el = document.getElementById('stat-total-users');
  if (el) {
    el.textContent = allUsers.length;
  }
  updateDeviceStats();
}

// fill department dropdown options (both create and edit modals)
function fillDepartmentDropdowns() {
  var html = '';
  for (var i = 0; i < departments.length; i++) {
    html += '<option value="' + departments[i].name + '">' + departments[i].name + '</option>';
  }

  var createSelect = document.getElementById('new-dept');
  if (createSelect) {
    createSelect.innerHTML = html;
  }

  var editSelect = document.getElementById('edit-dept-select');
  if (editSelect) {
    var previousValue = editSelect.value;
    editSelect.innerHTML = html;
    // restore previously selected value if still available
    if (previousValue) {
      editSelect.value = previousValue;
    }
  }
}

// draw the department list in the modal
function renderDepartmentList() {
  var list = document.getElementById('dept-list');
  var html = '';

  for (var i = 0; i < departments.length; i++) {
    var dept = departments[i];
    html += '<li>';
    html += '<i class="fas fa-building blue-text"></i> ' + dept.name;
    html += '<span style="margin-left:auto">';
    html += '<button class="tbl-btn danger" onclick="removeDepartment(\'' + dept._id + '\', \'' + dept.name + '\')">';
    html += '<i class="fas fa-trash"></i>';
    html += '</button>';
    html += '</span>';
    html += '</li>';
  }

  list.innerHTML = html;
}


// ========== USER ACTIONS ==========

// open the full edit user modal
function openEditUser(userId) {
  var user = null;
  for (var i = 0; i < allUsers.length; i++) {
    if (allUsers[i]._id === userId) {
      user = allUsers[i];
      break;
    }
  }
  if (!user) return;

  editingUserId = userId;

  // fill the form with current values
  document.getElementById('edit-name').value = user.name;
  document.getElementById('edit-email').value = user.email;
  document.getElementById('edit-role-select').value = user.role;
  document.getElementById('edit-status-select').value = user.status;
  document.getElementById('edit-mfa').checked = user.mfa;

  // fill department dropdown
  var deptSelect = document.getElementById('edit-dept-select');
  var deptHtml = '';
  for (var j = 0; j < departments.length; j++) {
    deptHtml += '<option value="' + departments[j].name + '">' + departments[j].name + '</option>';
  }
  deptSelect.innerHTML = deptHtml;
  deptSelect.value = user.department;

  openModal('edit-user-modal');
}

// remove a user
async function removeUser(userId) {
  var user = null;
  for (var i = 0; i < allUsers.length; i++) {
    if (allUsers[i]._id === userId) {
      user = allUsers[i];
      break;
    }
  }
  if (!user) {
    console.error('removeUser: user not found in allUsers for id', userId);
    return;
  }

  if (!confirm('Remove user "' + user.name + '" (' + user.email + ')?')) return;

  try {
    var response = await fetch('/api/users/' + userId, { method: 'DELETE' });
    var data = await response.json();

    if (response.ok) {
      await loadUsers();
      updateStats();
    } else {
      alert(data.error || 'Failed to remove user');
      console.error('Delete failed:', data);
    }
  } catch (err) {
    alert('Failed to remove user');
    console.error('Delete error:', err);
  }
}


// ========== DEPARTMENT ACTIONS ==========

// add a new department
async function addDepartment() {
  var input = document.getElementById('new-dept-name');
  var name = input.value.trim();
  if (!name) return;

  try {
    var response = await fetch('/api/departments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name })
    });
    var data = await response.json();

    if (!response.ok) {
      alert(data.error);
      return;
    }

    input.value = '';
    await loadDepartments();
  } catch (err) {
    alert('Failed to add department');
  }
}

// remove a department
async function removeDepartment(deptId, deptName) {
  // check if any user is in this department
  var inUse = false;
  for (var i = 0; i < allUsers.length; i++) {
    if (allUsers[i].department === deptName) {
      inUse = true;
      break;
    }
  }

  if (inUse) {
    alert('Cannot remove "' + deptName + '" because it is assigned to users. Change their department first.');
    return;
  }

  if (!confirm('Remove department "' + deptName + '"?')) return;

  try {
    var response = await fetch('/api/departments/' + deptId, { method: 'DELETE' });
    var data = await response.json();

    if (response.ok) {
      await loadDepartments();
    } else {
      alert(data.error || 'Failed to remove department');
    }
  } catch (err) {
    alert('Failed to remove department');
  }
}


// ========== PROFILE ==========

function openProfileModal() {
  if (!currentUser || !currentUser._id) return;

  // fill the modal with current user data
  document.getElementById('profile-avatar-letter').textContent = (currentUser.name || '?')[0].toUpperCase();
  document.getElementById('profile-display-name').textContent = currentUser.name;
  document.getElementById('profile-display-role').textContent = currentUser.role + ' — ' + currentUser.department;
  document.getElementById('profile-name').value = currentUser.name || '';
  document.getElementById('profile-email').value = currentUser.email || '';
  document.getElementById('profile-phone').value = currentUser.phone || '';
  document.getElementById('profile-gender').value = currentUser.gender || '';
  document.getElementById('profile-department').value = currentUser.department || '';
  document.getElementById('profile-status').value = currentUser.status || '';

  // clear password fields and messages
  document.getElementById('pw-current').value = '';
  document.getElementById('pw-new').value = '';
  hideMsg('profile-msg');
  hideMsg('pw-msg');

  openModal('profile-modal');
}

// save profile (name, phone, gender)
document.addEventListener('DOMContentLoaded', function () {

  document.getElementById('profile-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    hideMsg('profile-msg');

    var name = document.getElementById('profile-name').value.trim();
    var phone = document.getElementById('profile-phone').value.trim();
    var gender = document.getElementById('profile-gender').value;

    if (!name) {
      showMsg('profile-msg', 'Name is required', 'err');
      return;
    }

    try {
      var response = await fetch('/api/auth/profile/' + currentUser._id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, phone: phone, gender: gender })
      });
      var data = await response.json();

      if (!response.ok) {
        showMsg('profile-msg', data.error || 'Update failed', 'err');
        return;
      }

      // update local user data
      currentUser.name = data.user.name;
      currentUser.phone = data.user.phone;
      currentUser.gender = data.user.gender;

      // update header and greeting
      document.getElementById('profile-avatar-letter').textContent = currentUser.name[0].toUpperCase();
      document.getElementById('profile-display-name').textContent = currentUser.name;

      if (currentUser.role === 'Super Admin') {
        document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
      } else {
        document.getElementById('user-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
      }

      showMsg('profile-msg', 'Profile updated successfully!', 'success');
    } catch (err) {
      showMsg('profile-msg', 'Failed to update profile', 'err');
    }
  });

  // change password
  document.getElementById('password-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    hideMsg('pw-msg');

    var currentPw = document.getElementById('pw-current').value;
    var newPw = document.getElementById('pw-new').value;

    if (!currentPw || !newPw) {
      showMsg('pw-msg', 'Both fields are required', 'err');
      return;
    }

    if (newPw.length < 8) {
      showMsg('pw-msg', 'New password must be at least 8 characters', 'err');
      return;
    }

    try {
      var response = await fetch('/api/auth/profile/' + currentUser._id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword: currentPw, newPassword: newPw })
      });
      var data = await response.json();

      if (!response.ok) {
        showMsg('pw-msg', data.error || 'Password change failed', 'err');
        return;
      }

      document.getElementById('pw-current').value = '';
      document.getElementById('pw-new').value = '';
      showMsg('pw-msg', 'Password changed successfully!', 'success');
    } catch (err) {
      showMsg('pw-msg', 'Failed to change password', 'err');
    }
  });
});

function showMsg(id, text, type) {
  var el = document.getElementById(id);
  el.textContent = text;
  el.className = 'profile-msg ' + type;
}

function hideMsg(id) {
  var el = document.getElementById(id);
  el.textContent = '';
  el.className = 'profile-msg hide';
}


// ========== TAB HELPERS ==========

function switchToTab(tabId) {
  // deactivate all tabs and content
  var allTabs = document.querySelectorAll('.tab');
  var allContent = document.querySelectorAll('.tab-content');
  for (var i = 0; i < allTabs.length; i++) {
    allTabs[i].classList.remove('active');
  }
  for (var j = 0; j < allContent.length; j++) {
    allContent[j].classList.remove('active');
  }
  // activate the target tab and content
  var tabButton = document.querySelector('.tab[data-tab="' + tabId + '"]');
  if (tabButton) tabButton.classList.add('active');
  var tabContent = document.getElementById(tabId);
  if (tabContent) tabContent.classList.add('active');
}


// ========== MODAL HELPERS ==========

function openModal(modalId) {
  document.getElementById(modalId).classList.remove('hide');
  if (modalId === 'dept-modal') renderDepartmentList();
  if (modalId === 'create-user-modal') fillDepartmentDropdowns();
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.add('hide');
}


// ========== DEVICE INFO & FINGERPRINT ==========

function getDeviceInfo() {
  var ua = navigator.userAgent;

  // browser detection
  var browser = 'Unknown';
  if (ua.indexOf('Firefox') > -1) browser = 'Firefox';
  else if (ua.indexOf('Edg') > -1) browser = 'Microsoft Edge';
  else if (ua.indexOf('Chrome') > -1) browser = 'Chrome';
  else if (ua.indexOf('Safari') > -1) browser = 'Safari';
  else if (ua.indexOf('Opera') > -1 || ua.indexOf('OPR') > -1) browser = 'Opera';

  // OS detection
  var os = 'Unknown';
  if (ua.indexOf('Windows') > -1) os = 'Windows';
  else if (ua.indexOf('Mac') > -1) os = 'macOS';
  else if (ua.indexOf('Linux') > -1) os = 'Linux';
  else if (ua.indexOf('Android') > -1) os = 'Android';
  else if (ua.indexOf('iPhone') > -1 || ua.indexOf('iPad') > -1) os = 'iOS';

  // device health assessment
  var health = 'Good';
  if (!window.isSecureContext) health = 'Poor — Not HTTPS';
  else if (navigator.cookieEnabled === false) health = 'Fair — Cookies Disabled';

  // simple fingerprint from browser properties
  var fingerprint = generateFingerprint();

  return {
    browser: browser + ' (' + os + ')',
    os: os,
    deviceHealth: health,
    ipAddress: '',  // will be filled by geolocation API
    geoLocation: '', // will be filled by geolocation API
    fingerprint: fingerprint
  };
}

function generateFingerprint() {
  var components = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    screen.colorDepth,
    new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency || 'unknown',
    navigator.platform || 'unknown'
  ];
  // simple hash
  var str = components.join('|');
  var hash = 0;
  for (var i = 0; i < str.length; i++) {
    var char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // convert to 32-bit integer
  }
  return 'DEV-' + Math.abs(hash).toString(16).toUpperCase();
}

// fetch IP and geo location from free API
async function fetchIPInfo() {
  try {
    var response = await fetch('https://ipapi.co/json/');
    var data = await response.json();
    return {
      ip: data.ip || '',
      geo: (data.city || '') + ', ' + (data.region || '') + ', ' + (data.country_name || '')
    };
  } catch (err) {
    return { ip: 'Unknown', geo: 'Unknown' };
  }
}


// ========== DEVICE APPROVALS (ADMIN) ==========

async function loadDevices() {
  try {
    var response = await fetch('/api/devices');
    allDevices = await response.json();
    renderDevicesTable();
    updateDeviceStats();
  } catch (err) {
    console.error('Failed to load devices', err);
  }
}

function renderDevicesTable() {
  var tbody = document.getElementById('devices-table-body');
  if (!tbody) return;
  var html = '';

  var filtered = allDevices;
  if (deviceFilter !== 'all') {
    filtered = [];
    for (var i = 0; i < allDevices.length; i++) {
      if (allDevices[i].status === deviceFilter) {
        filtered.push(allDevices[i]);
      }
    }
  }

  if (filtered.length === 0) {
    html = '<tr><td colspan="9" style="text-align:center;color:#94a3b8;padding:32px;">No device requests found</td></tr>';
    tbody.innerHTML = html;
    return;
  }

  for (var j = 0; j < filtered.length; j++) {
    var d = filtered[j];

    var statusBadge = 'orange-bg';
    if (d.status === 'Approved') statusBadge = 'green-bg';
    if (d.status === 'Rejected') statusBadge = 'red-bg';

    var healthBadge = 'green-bg';
    if (d.device_health && d.device_health.indexOf('Fair') > -1) healthBadge = 'orange-bg';
    if (d.device_health && d.device_health.indexOf('Poor') > -1) healthBadge = 'red-bg';

    var dateStr = d.created_at ? new Date(d.created_at).toLocaleString() : '—';
    var approvedBy = d.approved_by || '—';

    html += '<tr>';
    html += '<td><strong>' + (d.user_name || '—') + '</strong><br><small class="muted">' + (d.user_email || '') + '</small></td>';
    html += '<td><code>' + (d.ip_address || '—') + '</code></td>';
    html += '<td>' + (d.geo_location || '—') + '</td>';
    html += '<td><span class="badge ' + healthBadge + '">' + (d.device_health || 'Unknown') + '</span></td>';
    html += '<td>' + (d.browser || '—') + '</td>';
    html += '<td><span class="badge ' + statusBadge + '">' + d.status + '</span></td>';
    html += '<td>' + approvedBy + '</td>';
    html += '<td><small>' + dateStr + '</small></td>';
    html += '<td class="td-actions">';

    if (d.status === 'Pending') {
      html += '<button class="tbl-btn success" onclick="approveDevice(\'' + d.id + '\')" title="Approve"><i class="fas fa-check"></i></button>';
      html += '<button class="tbl-btn danger" onclick="rejectDevice(\'' + d.id + '\')" title="Reject"><i class="fas fa-times"></i></button>';
    } else {
      html += '<button class="tbl-btn danger" onclick="deleteDevice(\'' + d.id + '\')" title="Delete"><i class="fas fa-trash"></i></button>';
    }

    html += '</td>';
    html += '</tr>';
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

  // update filter buttons
  var btns = document.querySelectorAll('.filter-btn');
  for (var i = 0; i < btns.length; i++) {
    btns[i].classList.remove('active');
  }
  event.target.classList.add('active');

  renderDevicesTable();
}

async function approveDevice(deviceId) {
  if (!confirm('Approve this device?')) return;
  try {
    var response = await fetch('/api/devices/' + deviceId + '/approve', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approvedBy: currentUser.email })
    });
    if (response.ok) {
      await loadDevices();
    } else {
      var data = await response.json();
      alert(data.error || 'Failed to approve');
    }
  } catch (err) {
    alert('Failed to approve device');
  }
}

async function rejectDevice(deviceId) {
  if (!confirm('Reject this device?')) return;
  try {
    var response = await fetch('/api/devices/' + deviceId + '/reject', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approvedBy: currentUser.email })
    });
    if (response.ok) {
      await loadDevices();
    } else {
      var data = await response.json();
      alert(data.error || 'Failed to reject');
    }
  } catch (err) {
    alert('Failed to reject device');
  }
}

async function deleteDevice(deviceId) {
  if (!confirm('Delete this device record?')) return;
  try {
    var response = await fetch('/api/devices/' + deviceId, { method: 'DELETE' });
    if (response.ok) {
      await loadDevices();
    } else {
      alert('Failed to delete device record');
    }
  } catch (err) {
    alert('Failed to delete device record');
  }
}

// user checks if their device has been approved
async function checkDeviceApproval() {
  if (!currentUser) return;

  var msgEl = document.getElementById('device-pending-msg');
  msgEl.textContent = 'Checking...';
  msgEl.className = 'profile-msg';

  var fingerprint = generateFingerprint();

  try {
    var response = await fetch('/api/devices/check/' + currentUser._id + '/' + fingerprint);
    var data = await response.json();

    if (data.approved) {
      msgEl.textContent = 'Device approved! Redirecting...';
      msgEl.className = 'profile-msg success';

      setTimeout(function () {
        if (currentUser.role === 'Admin') {
          document.getElementById('admin-email').textContent = currentUser.email;
          document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
          loadUsers();
          loadDepartments();
          loadDevices();
          updateStats();
          showPage('admin-dashboard');
        } else {
          document.getElementById('user-email').textContent = currentUser.email;
          document.getElementById('user-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
          showPage('user-dashboard');
        }
      }, 1500);
    } else {
      msgEl.textContent = 'Still pending. Please wait for admin approval.';
      msgEl.className = 'profile-msg err';
    }
  } catch (err) {
    msgEl.textContent = 'Failed to check status';
    msgEl.className = 'profile-msg err';
  }
}
