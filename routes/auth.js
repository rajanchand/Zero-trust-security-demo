// ============================================
// ZTS — Authentication Routes
// NIST SP 800-207: Identity Verification
// ============================================
// Implements: Password auth, OTP MFA, adaptive auth,
// account lockout, risk scoring, VPN detection,
// impossible travel, session creation, IP checking

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { logEvent } = require('./audit');
const { checkIP } = require('./ip-rules');
const { getPolicy } = require('./policies');
const { calculateRiskScore, detectVPN, detectImpossibleTravel } = require('./risk');

// Gmail transporter for OTP
var transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// Send OTP email
async function sendOtpEmail(toEmail, otpCode) {
  await transporter.sendMail({
    from: '"ZTS Security" <' + process.env.GMAIL_USER + '>',
    to: toEmail,
    subject: 'Your ZTS Login OTP — ' + otpCode,
    html: '<div style="font-family:sans-serif;max-width:400px;margin:0 auto;text-align:center;padding:30px">'
      + '<h2 style="color:#0ea5e9">🔒 Zero Trust Security</h2>'
      + '<p style="color:#64748b">Your one-time verification code:</p>'
      + '<div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#0ea5e9;'
      + 'background:#f0f9ff;border-radius:12px;padding:20px;margin:20px 0">'
      + otpCode + '</div>'
      + '<p style="color:#94a3b8;font-size:13px">Expires in 60 seconds. Do not share this code.</p>'
      + '</div>'
  });
}

// ===== LOGIN =====
// NIST: Verify identity, check IP rules, detect VPN, calculate risk
router.post('/login', async (req, res) => {
  var supabase = req.app.locals.supabase;
  var otpStore = req.app.locals.otpStore;

  try {
    var { email, password } = req.body;
    var clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // IP restriction check
    var ipCheck = await checkIP(supabase, clientIp);
    if (!ipCheck.allowed) {
      await logEvent(supabase, { eventType: 'login_blocked_ip', severity: 'critical', userEmail: email.toLowerCase(), ipAddress: clientIp, details: ipCheck.reason });
      return res.status(403).json({ error: 'Access denied from your network' });
    }

    // Find user
    var { data: user, error } = await supabase.from('users').select('*').eq('email', email.toLowerCase()).single();

    if (error || !user) {
      await logEvent(supabase, { eventType: 'login_failed', severity: 'warning', userEmail: email.toLowerCase(), ipAddress: clientIp, details: 'User not found' });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if user is blocked
    if (user.is_blocked) {
      await logEvent(supabase, { eventType: 'login_blocked', severity: 'critical', userEmail: email.toLowerCase(), userId: user.id, ipAddress: clientIp, details: 'Account is blocked by admin' });
      return res.status(403).json({ error: 'Account blocked. Contact administrator.' });
    }

    // Check if user is suspended
    if (user.status === 'Suspended') {
      await logEvent(supabase, { eventType: 'login_blocked', severity: 'warning', userEmail: email.toLowerCase(), userId: user.id, ipAddress: clientIp, details: 'Account suspended' });
      return res.status(403).json({ error: 'Account suspended. Contact administrator.' });
    }

    // Check account lockout
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      var remaining = Math.ceil((new Date(user.locked_until).getTime() - Date.now()) / 60000);
      await logEvent(supabase, { eventType: 'login_locked', severity: 'warning', userEmail: email.toLowerCase(), userId: user.id, ipAddress: clientIp, details: 'Account locked for ' + remaining + ' more minutes' });
      return res.status(403).json({ error: 'Account locked. Try again in ' + remaining + ' minutes.' });
    }

    // Check max failed logins
    var maxFailed = parseInt(await getPolicy(supabase, 'max_failed_logins', '5'));
    if (user.failed_login_count >= maxFailed) {
      var lockoutMins = parseInt(await getPolicy(supabase, 'lockout_duration_minutes', '15'));
      var lockedUntil = new Date(Date.now() + lockoutMins * 60 * 1000).toISOString();
      await supabase.from('users').update({ locked_until: lockedUntil }).eq('id', user.id);
      await logEvent(supabase, { eventType: 'account_locked', severity: 'critical', userEmail: email.toLowerCase(), userId: user.id, ipAddress: clientIp, details: 'Locked for ' + lockoutMins + ' minutes after ' + maxFailed + ' failures' });

      // Log suspicious login
      await supabase.from('login_history').insert({
        user_id: user.id, user_email: user.email, ip_address: clientIp,
        risk_score: 100, risk_level: 'high', login_success: false, is_suspicious: true,
        risk_factors: [{ factor: 'Account Lockout', points: 100, detail: maxFailed + ' failed attempts' }]
      });

      return res.status(403).json({ error: 'Account locked due to too many failed attempts.' });
    }

    // Verify password
    var match = await bcrypt.compare(password, user.password);
    if (!match) {
      var newCount = (user.failed_login_count || 0) + 1;
      await supabase.from('users').update({ failed_login_count: newCount }).eq('id', user.id);

      await logEvent(supabase, { eventType: 'login_failed', severity: 'warning', userEmail: email.toLowerCase(), userId: user.id, ipAddress: clientIp, details: 'Wrong password (attempt ' + newCount + '/' + maxFailed + ')' });

      // Log failed attempt in login history
      await supabase.from('login_history').insert({
        user_id: user.id, user_email: user.email, ip_address: clientIp,
        risk_score: newCount * 10, risk_level: newCount >= 3 ? 'high' : 'medium',
        login_success: false, is_suspicious: newCount >= 3
      });

      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Password correct — generate OTP
    var code = String(Math.floor(100000 + Math.random() * 900000));
    otpStore.set(email.toLowerCase(), {
      code: code,
      expiresAt: Date.now() + 60000,
      userId: user.id,
      name: user.name,
      role: user.role,
      clientIp: clientIp
    });

    // Send OTP email
    try {
      await sendOtpEmail(email, code);
    } catch (mailErr) {
      console.error('OTP email error:', mailErr.message);
      return res.status(500).json({ error: 'Failed to send OTP. Check email config.' });
    }

    await logEvent(supabase, { eventType: 'otp_sent', severity: 'info', userEmail: email.toLowerCase(), userId: user.id, ipAddress: clientIp, details: 'OTP sent successfully' });

    res.json({
      message: 'OTP sent to your email',
      userId: user.id,
      name: user.name,
      role: user.role,
      email: email.toLowerCase()
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== RESEND OTP =====
router.post('/resend-otp', async (req, res) => {
  var supabase = req.app.locals.supabase;
  var otpStore = req.app.locals.otpStore;
  try {
    var { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    var { data: user } = await supabase.from('users').select('id, name, role').eq('email', email.toLowerCase()).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    var code = String(Math.floor(100000 + Math.random() * 900000));
    otpStore.set(email.toLowerCase(), { code: code, expiresAt: Date.now() + 60000, userId: user.id, name: user.name, role: user.role });

    try { await sendOtpEmail(email, code); } catch (e) { return res.status(500).json({ error: 'Failed to send OTP' }); }

    res.json({ message: 'OTP resent to your email' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== VERIFY OTP =====
// NIST: Complete identity verification, calculate risk, create session
router.post('/verify-otp', async (req, res) => {
  var supabase = req.app.locals.supabase;
  var otpStore = req.app.locals.otpStore;

  try {
    var { userId, code, deviceInfo } = req.body;
    var clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    if (!userId || !code) return res.status(400).json({ error: 'User ID and OTP code required' });

    // Find OTP
    var foundEmail = null;
    otpStore.forEach(function (value, key) {
      if (value.userId === userId) foundEmail = key;
    });

    if (!foundEmail) return res.status(400).json({ error: 'No OTP found. Please log in again.' });

    var otpData = otpStore.get(foundEmail);
    if (Date.now() > otpData.expiresAt) {
      otpStore.delete(foundEmail);
      return res.status(400).json({ error: 'OTP expired. Click Resend Code.' });
    }

    if (code !== otpData.code) {
      await logEvent(supabase, { eventType: 'otp_failed', severity: 'warning', userEmail: foundEmail, userId: userId, ipAddress: clientIp, details: 'Invalid OTP entered' });
      return res.status(400).json({ error: 'Invalid OTP code' });
    }

    // OTP correct — clean up
    otpStore.delete(foundEmail);

    // Get full user data
    var { data: user } = await supabase.from('users').select('*').eq('id', userId).single();
    if (!user) return res.status(404).json({ error: 'User not found' });

    // ===== RISK ASSESSMENT =====
    var vpnDetected = detectVPN(clientIp);
    var impossibleTravel = detectImpossibleTravel(user.last_login_at, user.last_country, deviceInfo ? deviceInfo.country : '');
    var ipChanged = user.last_login_ip && user.last_login_ip !== clientIp;

    // Check if device is approved
    var deviceApproved = true;
    if (deviceInfo && deviceInfo.fingerprint) {
      var { data: devCheck } = await supabase
        .from('device_approvals')
        .select('status')
        .eq('user_id', userId)
        .eq('fingerprint', deviceInfo.fingerprint)
        .eq('status', 'Approved')
        .limit(1);
      deviceApproved = devCheck && devCheck.length > 0;
    }

    var riskResult = calculateRiskScore({
      deviceApproved: deviceApproved,
      currentCountry: deviceInfo ? deviceInfo.country : '',
      lastCountry: user.last_country || '',
      failedLogins: user.failed_login_count || 0,
      vpnDetected: vpnDetected,
      isAdmin: user.role === 'SuperAdmin' || user.role === 'Admin',
      ipChanged: ipChanged,
      impossibleTravel: impossibleTravel
    });

    var isSuspicious = riskResult.score > 60 || impossibleTravel || vpnDetected;

    // Update user record
    await supabase.from('users').update({
      failed_login_count: 0,
      last_login_ip: clientIp,
      last_login_at: new Date().toISOString(),
      last_country: deviceInfo ? deviceInfo.country : user.last_country,
      last_risk_score: riskResult.score,
      locked_until: null
    }).eq('id', userId);

    // Save risk score
    await supabase.from('users').update({ last_risk_score: riskResult.score }).eq('id', userId);

    // Create login history entry
    await supabase.from('login_history').insert({
      user_id: userId,
      user_email: user.email,
      ip_address: clientIp,
      country: deviceInfo ? deviceInfo.country : '',
      city: deviceInfo ? deviceInfo.city : '',
      browser: deviceInfo ? deviceInfo.browser : '',
      os: deviceInfo ? deviceInfo.os : '',
      device_fingerprint: deviceInfo ? deviceInfo.fingerprint : '',
      risk_score: riskResult.score,
      risk_level: riskResult.level,
      risk_factors: riskResult.factors,
      vpn_detected: vpnDetected,
      is_suspicious: isSuspicious,
      login_success: true
    });

    // Create session
    var sessionTimeout = parseInt(await getPolicy(supabase, 'session_timeout_minutes', '30'));
    var sessionData = null;
    try {
      var { data: sess } = await supabase.from('sessions').insert({
        user_id: userId,
        user_email: user.email,
        user_name: user.name,
        user_role: user.role,
        ip_address: clientIp,
        browser: deviceInfo ? deviceInfo.browser : '',
        os: deviceInfo ? deviceInfo.os : '',
        fingerprint: deviceInfo ? deviceInfo.fingerprint : '',
        geo_location: deviceInfo ? deviceInfo.geoLocation : '',
        country: deviceInfo ? deviceInfo.country : '',
        expires_at: new Date(Date.now() + sessionTimeout * 60 * 1000).toISOString(),
        is_active: true
      }).select('*').single();
      sessionData = sess;
    } catch (e) { console.error('Session error:', e.message); }

    await logEvent(supabase, {
      eventType: 'login_success',
      severity: isSuspicious ? 'warning' : 'info',
      userEmail: user.email,
      userId: userId,
      ipAddress: clientIp,
      details: 'Login successful — risk: ' + riskResult.score + ' (' + riskResult.level + ')' + (vpnDetected ? ' [VPN]' : '') + (impossibleTravel ? ' [IMPOSSIBLE TRAVEL]' : '')
    });

    res.json({
      message: 'Verified',
      user: {
        _id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        status: user.status,
        mfa: user.mfa,
        phone: user.phone || '',
        gender: user.gender || '',
        createdAt: user.created_at,
        riskScore: riskResult.score,
        riskLevel: riskResult.level,
        riskFactors: riskResult.factors,
        sessionId: sessionData ? sessionData.id : null,
        sessionExpiresAt: sessionData ? sessionData.expires_at : null,
        vpnDetected: vpnDetected,
        impossibleTravel: impossibleTravel
      }
    });
  } catch (err) {
    console.error('Verify OTP error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ===== PROFILE =====
router.get('/profile/:id', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data } = await supabase.from('users').select('*').eq('id', req.params.id).single();
    if (!data) return res.status(404).json({ error: 'User not found' });

    res.json({
      _id: data.id, name: data.name, email: data.email, role: data.role,
      department: data.department, status: data.status, mfa: data.mfa,
      phone: data.phone || '', gender: data.gender || '', createdAt: data.created_at
    });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

router.put('/profile/:id', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var updates = {};
    if (req.body.name) updates.name = req.body.name;
    if (req.body.phone !== undefined) updates.phone = req.body.phone;
    if (req.body.gender !== undefined) updates.gender = req.body.gender;

    if (req.body.currentPassword && req.body.newPassword) {
      var { data: u } = await supabase.from('users').select('password').eq('id', req.params.id).single();
      if (!u) return res.status(404).json({ error: 'User not found' });

      var match = await bcrypt.compare(req.body.currentPassword, u.password);
      if (!match) return res.status(400).json({ error: 'Current password is incorrect' });

      var minLen = parseInt(await getPolicy(supabase, 'password_min_length', '8'));
      if (req.body.newPassword.length < minLen) return res.status(400).json({ error: 'Password must be at least ' + minLen + ' characters' });

      updates.password = await bcrypt.hash(req.body.newPassword, 10);
      await logEvent(supabase, { eventType: 'password_changed', severity: 'info', userId: req.params.id, details: 'Password changed' });
    }

    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No fields to update' });

    var { data, error } = await supabase.from('users').update(updates).eq('id', req.params.id).select('*').single();
    if (error) throw error;

    await logEvent(supabase, { eventType: 'profile_updated', severity: 'info', userId: req.params.id, userEmail: data.email, details: 'Profile updated' });

    res.json({
      message: 'Profile updated',
      user: { _id: data.id, name: data.name, email: data.email, role: data.role, department: data.department, status: data.status, mfa: data.mfa, phone: data.phone || '', gender: data.gender || '', createdAt: data.created_at }
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

module.exports = router;
