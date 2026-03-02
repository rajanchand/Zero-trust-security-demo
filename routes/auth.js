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
      .select('id, name, email, role, department, status, mfa, phone, gender, created_at')
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
    res.status(500).json({ error: 'Server error' });
  }
});

// get user profile
router.get('/profile/:id', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { data, error } = await supabase
      .from('users')
      .select('id, name, email, role, department, status, mfa, phone, gender, created_at')
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
      .select('id, name, email, role, department, status, mfa, phone, gender, created_at')
      .single();

    if (error) throw error;

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
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

module.exports = router;
