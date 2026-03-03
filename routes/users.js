// ============================================
// ZTS — User Management Routes
// NIST SP 800-207: Least Privilege Access
// ============================================
// Implements: RBAC, user CRUD, block/unblock,
// reset password, enable/disable MFA

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { logEvent } = require('./audit');

// Roles for RBAC (ordered by privilege)
const VALID_ROLES = ['SuperAdmin', 'HR', 'Finance', 'IT', 'CustomerSupport'];

// GET all users (admin only)
router.get('/', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data, error } = await supabase.from('users')
      .select('id, name, email, role, department, status, mfa, phone, gender, created_at, last_login_at, last_risk_score, failed_login_count, last_login_ip, is_blocked')
      .order('created_at', { ascending: false });

    if (error) throw error;

    var users = (data || []).map(function (u) {
      return {
        _id: u.id, name: u.name, email: u.email, role: u.role,
        department: u.department, status: u.status, mfa: u.mfa,
        phone: u.phone, gender: u.gender, createdAt: u.created_at,
        lastLoginAt: u.last_login_at, lastRiskScore: u.last_risk_score,
        failedLoginCount: u.failed_login_count, lastLoginIp: u.last_login_ip,
        isBlocked: u.is_blocked
      };
    });

    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// CREATE user
router.post('/', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { name, email, password, role, department } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });

    // Validate role
    if (role && VALID_ROLES.indexOf(role) === -1) return res.status(400).json({ error: 'Invalid role. Must be: ' + VALID_ROLES.join(', ') });

    // Check duplicate email
    var { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).limit(1);
    if (existing && existing.length > 0) return res.status(400).json({ error: 'Email already exists' });

    var hash = await bcrypt.hash(password, 10);
    var { data, error } = await supabase.from('users').insert({
      name: name, email: email.toLowerCase(), password: hash,
      role: role || 'CustomerSupport', department: department || 'General',
      status: 'Active', mfa: true
    }).select('*').single();

    if (error) throw error;

    await logEvent(supabase, { eventType: 'user_created', severity: 'info', userEmail: email.toLowerCase(), details: 'User created with role: ' + (role || 'CustomerSupport') });

    res.status(201).json({ message: 'User created', user: data });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to create user' });
  }
});

// UPDATE user
router.put('/:id', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var updates = {};
    if (req.body.name) updates.name = req.body.name;
    if (req.body.email) updates.email = req.body.email.toLowerCase();
    if (req.body.role) {
      if (VALID_ROLES.indexOf(req.body.role) === -1) return res.status(400).json({ error: 'Invalid role' });
      updates.role = req.body.role;
    }
    if (req.body.department) updates.department = req.body.department;
    if (req.body.status) updates.status = req.body.status;
    if (req.body.mfa !== undefined) updates.mfa = req.body.mfa;
    if (req.body.password) updates.password = await bcrypt.hash(req.body.password, 10);

    var { data, error } = await supabase.from('users').update(updates).eq('id', req.params.id).select('*').single();
    if (error) throw error;

    await logEvent(supabase, { eventType: 'user_updated', severity: 'info', userEmail: data.email, details: 'Updated: ' + Object.keys(updates).join(', ') });

    res.json({ message: 'User updated', user: data });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Failed to update user' });
  }
});

// DELETE user
router.delete('/:id', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data: user } = await supabase.from('users').select('email').eq('id', req.params.id).single();
    await supabase.from('users').delete().eq('id', req.params.id);
    if (user) await logEvent(supabase, { eventType: 'user_deleted', severity: 'warning', userEmail: user.email, details: 'User deleted' });
    res.json({ message: 'User deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// BLOCK/UNBLOCK user
router.put('/:id/block', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var blocked = req.body.blocked !== false;
    var { data, error } = await supabase.from('users').update({ is_blocked: blocked }).eq('id', req.params.id).select('email').single();
    if (error) throw error;

    await logEvent(supabase, { eventType: blocked ? 'user_blocked' : 'user_unblocked', severity: 'warning', userEmail: data.email, details: (blocked ? 'Blocked' : 'Unblocked') + ' by admin' });

    res.json({ message: blocked ? 'User blocked' : 'User unblocked' });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// RESET PASSWORD (admin)
router.put('/:id/reset-password', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var newPassword = req.body.password || 'ZTS@2026';
    var hash = await bcrypt.hash(newPassword, 10);
    var { data, error } = await supabase.from('users')
      .update({ password: hash, failed_login_count: 0, locked_until: null })
      .eq('id', req.params.id).select('email').single();
    if (error) throw error;

    await logEvent(supabase, { eventType: 'password_reset', severity: 'warning', userEmail: data.email, details: 'Password reset by admin' });

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

// TOGGLE MFA
router.put('/:id/toggle-mfa', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data: user } = await supabase.from('users').select('mfa, email').eq('id', req.params.id).single();
    if (!user) return res.status(404).json({ error: 'Not found' });

    var newMfa = !user.mfa;
    await supabase.from('users').update({ mfa: newMfa }).eq('id', req.params.id);
    await logEvent(supabase, { eventType: 'mfa_toggled', severity: 'info', userEmail: user.email, details: 'MFA ' + (newMfa ? 'enabled' : 'disabled') });

    res.json({ message: 'MFA ' + (newMfa ? 'enabled' : 'disabled'), mfa: newMfa });
  } catch (err) {
    res.status(500).json({ error: 'Failed' });
  }
});

module.exports = router;
