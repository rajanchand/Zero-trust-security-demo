const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { logEvent } = require('./audit');
const { checkIP } = require('./ip-rules');
const { getPolicy } = require('./policies');

// Gmail transporter – uses App Password (not regular password)
var transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD
  }
});

// send OTP email helper
async function sendOtpEmail(toEmail, otpCode) {
  await transporter.sendMail({
    from: '"Zero Trust Security" <' + process.env.GMAIL_USER + '>',
    to: toEmail,
    subject: 'Your Login OTP Code — ' + otpCode,
    html: '<div style="font-family:sans-serif;max-width:400px;margin:0 auto;text-align:center;padding:30px">'
      + '<h2 style="color:#1e40af">Zero Trust Security</h2>'
      + '<p style="color:#64748b">Your one-time verification code is:</p>'
      + '<div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#1e40af;'
      + 'background:#f0f9ff;border-radius:12px;padding:20px;margin:20px 0">'
      + otpCode + '</div>'
      + '<p style="color:#94a3b8;font-size:13px">This code expires in 60 seconds.<br>Do not share it with anyone.</p>'
      + '</div>'
  });
}

// ========== RISK SCORE ENGINE ==========
function calculateRiskScore(opts) {
  var score = 100; // start at max trust
  var factors = [];

  // 1. Device health (-20 for poor, -10 for fair)
  if (opts.deviceHealth) {
    if (opts.deviceHealth.indexOf('Poor') > -1) {
      score -= 20;
      factors.push({ factor: 'Device Health', impact: -20, detail: 'Not HTTPS' });
    } else if (opts.deviceHealth.indexOf('Fair') > -1) {
      score -= 10;
      factors.push({ factor: 'Device Health', impact: -10, detail: 'Cookies disabled' });
    } else {
      factors.push({ factor: 'Device Health', impact: 0, detail: 'Good' });
    }
  }

  // 2. Known IP (-15 if different from last login)
  if (opts.lastLoginIp && opts.currentIp && opts.lastLoginIp !== opts.currentIp) {
    score -= 15;
    factors.push({ factor: 'IP Address', impact: -15, detail: 'Different from last login' });
  } else {
    factors.push({ factor: 'IP Address', impact: 0, detail: 'Consistent' });
  }

  // 3. Failed login count (-5 per failure, max -25)
  if (opts.failedLogins > 0) {
    var penalty = Math.min(opts.failedLogins * 5, 25);
    score -= penalty;
    factors.push({ factor: 'Failed Logins', impact: -penalty, detail: opts.failedLogins + ' recent failures' });
  } else {
    factors.push({ factor: 'Failed Logins', impact: 0, detail: 'None' });
  }

  // 4. Geo-location check (-15 if unusual country)
  if (opts.geoLocation && opts.lastGeo && opts.lastGeo !== opts.geoLocation) {
    // only penalize if both are non-empty and different
    if (opts.lastGeo.length > 3 && opts.geoLocation.length > 3) {
      score -= 15;
      factors.push({ factor: 'Geo Location', impact: -15, detail: 'Location changed' });
    }
  } else {
    factors.push({ factor: 'Geo Location', impact: 0, detail: 'Consistent' });
  }

  // 5. New device (-10 if device not approved)
  if (!opts.deviceApproved) {
    score -= 10;
    factors.push({ factor: 'Device Trust', impact: -10, detail: 'New or unapproved device' });
  } else {
    factors.push({ factor: 'Device Trust', impact: 0, detail: 'Approved device' });
  }

  // 6. Time of day (-5 if outside business hours)
  var hour = new Date().getUTCHours();
  if (hour < 6 || hour > 22) {
    score -= 5;
    factors.push({ factor: 'Time of Day', impact: -5, detail: 'Off-hours access' });
  } else {
    factors.push({ factor: 'Time of Day', impact: 0, detail: 'Business hours' });
  }

  // clamp score to 0-100
  score = Math.max(0, Math.min(100, score));

  return { score: score, factors: factors };
}


// login - check email and password, generate OTP and send to Gmail
router.post('/login', async (req, res) => {
  const supabase = req.app.locals.supabase;
  const otpStore = req.app.locals.otpStore;

  try {
    const { email, password } = req.body;
    var clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // IP check
    var ipCheck = await checkIP(supabase, clientIp);
    if (!ipCheck.allowed) {
      await logEvent(supabase, {
        eventType: 'login_blocked_ip',
        severity: 'critical',
        userEmail: email.toLowerCase(),
        ipAddress: clientIp,
        details: 'Login blocked — ' + ipCheck.reason
      });
      return res.status(403).json({ error: 'Access denied from your network' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      await logEvent(supabase, {
        eventType: 'login_failed',
        severity: 'warning',
        userEmail: email.toLowerCase(),
        ipAddress: clientIp,
        details: 'Invalid email — user not found'
      });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if user is suspended
    if (user.status === 'Suspended') {
      await logEvent(supabase, {
        eventType: 'login_blocked_suspended',
        severity: 'warning',
        userEmail: email.toLowerCase(),
        userId: user.id,
        ipAddress: clientIp,
        details: 'Login blocked — user account is suspended'
      });
      return res.status(403).json({ error: 'Account is suspended. Contact administrator.' });
    }

    // check max failed logins policy
    var maxFailed = parseInt(await getPolicy(supabase, 'max_failed_logins', '5'));
    if (user.failed_login_count >= maxFailed) {
      await logEvent(supabase, {
        eventType: 'login_blocked_lockout',
        severity: 'critical',
        userEmail: email.toLowerCase(),
        userId: user.id,
        ipAddress: clientIp,
        details: 'Account locked — ' + user.failed_login_count + ' failed attempts (max: ' + maxFailed + ')'
      });
      return res.status(403).json({ error: 'Account locked due to too many failed attempts. Contact administrator.' });
    }

    var match = await bcrypt.compare(password, user.password);
    if (!match) {
      // increment failed login count
      var newCount = (user.failed_login_count || 0) + 1;
      await supabase.from('users').update({ failed_login_count: newCount }).eq('id', user.id);

      await logEvent(supabase, {
        eventType: 'login_failed',
        severity: 'warning',
        userEmail: email.toLowerCase(),
        userId: user.id,
        ipAddress: clientIp,
        details: 'Wrong password (attempt ' + newCount + '/' + maxFailed + ')'
      });
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // password correct — generate OTP
    var code = String(Math.floor(100000 + Math.random() * 900000));

    // store OTP with user info
    otpStore.set(email.toLowerCase(), {
      code: code,
      expiresAt: Date.now() + 60000,
      userId: user.id,
      name: user.name,
      role: user.role
    });

    // send OTP email
    try {
      await sendOtpEmail(email, code);
      console.log('OTP sent to ' + email);
    } catch (mailErr) {
      console.error('Failed to send OTP email:', mailErr.message);
      return res.status(500).json({ error: 'Failed to send OTP email. Check server email configuration.' });
    }

    await logEvent(supabase, {
      eventType: 'otp_sent',
      severity: 'info',
      userEmail: email.toLowerCase(),
      userId: user.id,
      ipAddress: clientIp,
      details: 'OTP sent successfully'
    });

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

// resend OTP - re-generates and re-sends OTP to email
router.post('/resend-otp', async (req, res) => {
  const supabase = req.app.locals.supabase;
  const otpStore = req.app.locals.otpStore;
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // find the user
    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, role')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // generate new OTP
    var code = String(Math.floor(100000 + Math.random() * 900000));

    otpStore.set(email.toLowerCase(), {
      code: code,
      expiresAt: Date.now() + 60000,
      userId: user.id,
      name: user.name,
      role: user.role
    });

    try {
      await sendOtpEmail(email, code);
    } catch (mailErr) {
      console.error('Failed to resend OTP:', mailErr.message);
      return res.status(500).json({ error: 'Failed to send OTP. Check email configuration.' });
    }

    res.json({ message: 'OTP resent to your email' });
  } catch (err) {
    console.error('Resend OTP error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// verify OTP - validate code server-side and return user data
router.post('/verify-otp', async (req, res) => {
  const supabase = req.app.locals.supabase;
  const otpStore = req.app.locals.otpStore;

  try {
    const { userId, code } = req.body;
    var clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

    if (!userId || !code) {
      return res.status(400).json({ error: 'User ID and OTP code are required' });
    }

    // find the OTP entry for this userId
    var foundEmail = null;
    otpStore.forEach(function (value, key) {
      if (value.userId === userId) {
        foundEmail = key;
      }
    });

    if (!foundEmail) {
      return res.status(400).json({ error: 'No OTP found. Please log in again.' });
    }

    var otpData = otpStore.get(foundEmail);

    // check expiry
    if (Date.now() > otpData.expiresAt) {
      otpStore.delete(foundEmail);
      return res.status(400).json({ error: 'OTP expired. Click Resend Code.' });
    }

    // check code
    if (code !== otpData.code) {
      await logEvent(supabase, {
        eventType: 'otp_failed',
        severity: 'warning',
        userEmail: foundEmail,
        userId: userId,
        ipAddress: clientIp,
        details: 'Invalid OTP code entered'
      });
      return res.status(400).json({ error: 'Invalid OTP code' });
    }

    // OTP correct! clean up
    otpStore.delete(foundEmail);

    // reset failed login count on successful login
    await supabase.from('users').update({
      failed_login_count: 0,
      last_login_ip: clientIp,
      last_login_at: new Date().toISOString()
    }).eq('id', userId);

    // get full user data
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: 'User not found' });
    }

    // calculate risk score
    var riskResult = calculateRiskScore({
      deviceHealth: '', // will be enriched by frontend
      lastLoginIp: data.last_login_ip || '',
      currentIp: clientIp,
      failedLogins: data.failed_login_count || 0,
      geoLocation: '',
      lastGeo: '',
      deviceApproved: true // we'll assume default for now, frontend enriches
    });

    // save risk score
    await supabase.from('users').update({ last_risk_score: riskResult.score }).eq('id', userId);

    // create session
    var sessionTimeout = parseInt(await getPolicy(supabase, 'session_timeout_minutes', '30'));
    var sessionRes = null;
    try {
      var { data: sessionData } = await supabase
        .from('sessions')
        .insert({
          user_id: userId,
          user_email: data.email,
          user_name: data.name,
          ip_address: clientIp,
          browser: '',
          os: '',
          fingerprint: '',
          geo_location: '',
          expires_at: new Date(Date.now() + sessionTimeout * 60 * 1000).toISOString(),
          is_active: true
        })
        .select('*')
        .single();
      sessionRes = sessionData;
    } catch (sessErr) {
      console.error('Session creation error:', sessErr.message);
    }

    await logEvent(supabase, {
      eventType: 'login_success',
      severity: 'info',
      userEmail: data.email,
      userId: userId,
      ipAddress: clientIp,
      details: 'Login successful — risk score: ' + riskResult.score
    });

    var user = {
      _id: data.id,
      name: data.name,
      email: data.email,
      role: data.role,
      department: data.department,
      status: data.status,
      mfa: data.mfa,
      phone: data.phone || '',
      gender: data.gender || '',
      createdAt: data.created_at,
      riskScore: riskResult.score,
      riskFactors: riskResult.factors,
      sessionId: sessionRes ? sessionRes.id : null,
      sessionExpiresAt: sessionRes ? sessionRes.expires_at : null
    };

    res.json({ message: 'Verified', user: user });
  } catch (err) {
    console.error('Verify OTP error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// get user profile
router.get('/profile/:id', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      _id: data.id,
      name: data.name,
      email: data.email,
      role: data.role,
      department: data.department,
      status: data.status,
      mfa: data.mfa,
      phone: data.phone || '',
      gender: data.gender || '',
      createdAt: data.created_at
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// update user profile (name, phone, gender, password)
router.put('/profile/:id', async (req, res) => {
  const supabase = req.app.locals.supabase;

  try {
    var updates = {};
    if (req.body.name) updates.name = req.body.name;
    if (req.body.phone !== undefined) updates.phone = req.body.phone;
    if (req.body.gender !== undefined) updates.gender = req.body.gender;

    // password change
    if (req.body.currentPassword && req.body.newPassword) {
      // verify current password
      const { data: user } = await supabase
        .from('users')
        .select('password')
        .eq('id', req.params.id)
        .single();

      if (!user) return res.status(404).json({ error: 'User not found' });

      var match = await bcrypt.compare(req.body.currentPassword, user.password);
      if (!match) {
        return res.status(400).json({ error: 'Current password is incorrect' });
      }

      // check min length policy
      var minLen = parseInt(await getPolicy(supabase, 'password_min_length', '8'));
      if (req.body.newPassword.length < minLen) {
        return res.status(400).json({ error: 'Password must be at least ' + minLen + ' characters' });
      }

      updates.password = await bcrypt.hash(req.body.newPassword, 10);

      await logEvent(supabase, {
        eventType: 'password_changed',
        severity: 'info',
        userId: req.params.id,
        details: 'Password changed successfully'
      });
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) {
      console.error('Profile update error:', error.message);
      if (error.message && error.message.includes('does not exist')) {
        return res.status(400).json({ error: 'Database needs migration. Run migrate.sql in Supabase SQL Editor.' });
      }
      throw error;
    }

    await logEvent(supabase, {
      eventType: 'profile_updated',
      severity: 'info',
      userId: req.params.id,
      userEmail: data.email,
      details: 'Profile updated: ' + Object.keys(updates).filter(function (k) { return k !== 'password'; }).join(', ')
    });

    res.json({
      message: 'Profile updated',
      user: {
        _id: data.id,
        name: data.name,
        email: data.email,
        role: data.role,
        department: data.department,
        status: data.status,
        mfa: data.mfa,
        phone: data.phone || '',
        gender: data.gender || '',
        createdAt: data.created_at
      }
    });
  } catch (err) {
    console.error('Profile update error:', err.message || err);
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

module.exports = router;
