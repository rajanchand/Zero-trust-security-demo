const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

// login - check email and password, generate OTP
router.post('/login', async (req, res) => {
  const supabase = req.app.locals.supabase;
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

    // generate 6-digit OTP (demo - returned in response)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    res.json({
      message: 'OTP sent',
      otp: otp,
      userId: user.id,
      name: user.name,
      role: user.role
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// verify OTP - return user data
router.post('/verify-otp', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { userId } = req.body;

    const { data, error } = await supabase
      .from('users')
      .select('id, name, email, role, department, status, mfa, created_at')
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
      createdAt: data.created_at
    };

    res.json({ message: 'Verified', user: user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
