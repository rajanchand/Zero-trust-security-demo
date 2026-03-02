// global variables
var currentUser = null;
var otp = null;
var otpTimer = null;
var departments = [];
var allUsers = [];
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
      otp = data.otp;
      document.getElementById('demo-otp').textContent = otp;
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

    // check if OTP expired
    if (!otp) {
      errorBox.textContent = 'OTP expired. Click Resend.';
      errorBox.classList.remove('hide');
      return;
    }

    // check if OTP matches
    if (code !== String(otp)) {
      errorBox.textContent = 'Wrong OTP.';
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
      return;
    }

    clearInterval(otpTimer);

    // verify with backend
    try {
      var response = await fetch('/api/auth/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: currentUser.userId })
      });
      var data = await response.json();

      if (!response.ok) {
        errorBox.textContent = data.error;
        errorBox.classList.remove('hide');
        return;
      }

      currentUser = data.user;

      // show the right dashboard based on role
      if (currentUser.role === 'Super Admin') {
        document.getElementById('admin-email').textContent = currentUser.email;
        document.getElementById('admin-greeting').textContent = 'Welcome, ' + currentUser.name + ' 👋';
        await loadUsers();
        await loadDepartments();
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
    var email = document.getElementById('email').value.trim();
    var password = document.getElementById('password').value;

    try {
      var response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
      });
      var data = await response.json();

      if (response.ok) {
        otp = data.otp;
        document.getElementById('demo-otp').textContent = otp;
        startOtpTimer();
      }
    } catch (err) {
      // silently fail
    }
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
      otp = null;
      document.getElementById('demo-otp').textContent = 'EXPIRED';
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


// ========== MODAL HELPERS ==========

function openModal(modalId) {
  document.getElementById(modalId).classList.remove('hide');
  if (modalId === 'dept-modal') renderDepartmentList();
  if (modalId === 'create-user-modal') fillDepartmentDropdowns();
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.add('hide');
}
