const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

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
  var mailOptions = {
    from: '"Zero Trust Security" <' + process.env.GMAIL_USER + '>',
    to: toEmail,
    subject: 'Your OTP Verification Code',
    html: '<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e0e0e0;border-radius:12px;">' +
      '<div style="text-align:center;margin-bottom:16px;">' +
      '<div style="background:#4F6EF7;color:#fff;width:48px;height:48px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:24px;">🔐</div>' +
      '</div>' +
      '<h2 style="text-align:center;color:#1a1a2e;">OTP Verification</h2>' +
      '<p style="text-align:center;color:#666;">Your one-time password for Zero Trust Security login:</p>' +
      '<div style="text-align:center;margin:24px 0;">' +
      '<span style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#4F6EF7;background:#f0f4ff;padding:12px 24px;border-radius:8px;display:inline-block;">' + otpCode + '</span>' +
      '</div>' +
      '<p style="text-align:center;color:#999;font-size:13px;">This code expires in <strong>60 seconds</strong>. Do not share it with anyone.</p>' +
      '<hr style="border:none;border-top:1px solid #eee;margin:20px 0;">' +
      '<p style="text-align:center;color:#aaa;font-size:11px;">Zero Trust Security &mdash; Never Trust, Always Verify</p>' +
      '</div>'
  };

  await transporter.sendMail(mailOptions);
}

// login - check email and password, generate OTP and send to Gmail
router.post('/login', async (req, res) => {
  const supabase = req.app.locals.supabase;
  const otpStore = req.app.locals.otpStore;
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.status === 'Suspended') {
      return res.status(403).json({ error: 'Account suspended' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // store OTP server-side with 60-second expiry
    otpStore.set(email.toLowerCase(), {
      code: otp,
      expiresAt: Date.now() + 60000,
      userId: user.id,
      name: user.name,
      role: user.role
    });

    // send OTP to user's email
    try {
      await sendOtpEmail(email, otp);
      console.log('OTP sent to ' + email);
    } catch (mailErr) {
      console.error('Failed to send OTP email:', mailErr.message);
      return res.status(500).json({ error: 'Failed to send OTP email. Check server email configuration.' });
    }

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

    // verify user still exists and is active
    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, role, status')
      .eq('email', email.toLowerCase())
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.status === 'Suspended') {
      return res.status(403).json({ error: 'Account suspended' });
    }

    // generate new 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // store OTP server-side with 60-second expiry
    otpStore.set(email.toLowerCase(), {
      code: otp,
      expiresAt: Date.now() + 60000,
      userId: user.id,
      name: user.name,
      role: user.role
    });

    // send OTP email
    try {
      await sendOtpEmail(email, otp);
      console.log('OTP resent to ' + email);
    } catch (mailErr) {
      console.error('Failed to resend OTP email:', mailErr.message);
      return res.status(500).json({ error: 'Failed to send OTP email' });
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

    if (!userId || !code) {
      return res.status(400).json({ error: 'User ID and OTP code are required' });
    }

    // find the OTP entry for this userId
    var foundEmail = null;
    var otpEntry = null;
    otpStore.forEach(function (value, key) {
      if (String(value.userId) === String(userId)) {
        foundEmail = key;
        otpEntry = value;
      }
    });

    if (!otpEntry) {
      return res.status(400).json({ error: 'No OTP found. Please login again.' });
    }

    // check expiry
    if (Date.now() > otpEntry.expiresAt) {
      otpStore.delete(foundEmail);
      return res.status(400).json({ error: 'OTP expired. Click Resend.' });
    }

    // check code
    if (code !== otpEntry.code) {
      return res.status(401).json({ error: 'Wrong OTP' });
    }

    // OTP valid — remove from store
    otpStore.delete(foundEmail);

    // fetch full user data
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', userId)
      .single();

    if (error || !data) {
      return res.status(404).json({ error: 'User not found' });
    }

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
      createdAt: data.created_at
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
    if (req.body.newPassword) {
      if (!req.body.currentPassword) {
        return res.status(400).json({ error: 'Current password is required' });
      }

      // verify current password
      const { data: user, error: fetchErr } = await supabase
        .from('users')
        .select('password')
        .eq('id', req.params.id)
        .single();

      if (fetchErr || !user) {
        return res.status(404).json({ error: 'User not found' });
      }

      const match = await bcrypt.compare(req.body.currentPassword, user.password);
      if (!match) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }

      updates.password = await bcrypt.hash(req.body.newPassword, 10);
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
      // if column doesn't exist, give helpful message
      if (error.message && error.message.includes('does not exist')) {
        return res.status(500).json({ error: 'Database migration needed. Please run migrate.sql in Supabase SQL Editor.' });
      }
      throw error;
    }

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
