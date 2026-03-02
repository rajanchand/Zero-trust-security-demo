const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

// helper: map supabase row to front-end shape (id -> _id)
function mapUser(row) {
  return {
    _id: row.id,
    name: row.name,
    email: row.email,
    role: row.role,
    department: row.department,
    status: row.status,
    mfa: row.mfa,
    phone: row.phone || '',
    gender: row.gender || '',
    createdAt: row.created_at
  };
}

// get all users (exclude super admin)
router.get('/', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { data, error } = await supabase
      .from('users')
      .select('*')
      .neq('role', 'Super Admin')
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(data.map(mapUser));
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// create a new user
router.post('/', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { name, email, password, role, department } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }

    // check if email already exists
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', email.toLowerCase());

    if (existing && existing.length > 0) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const hashed = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from('users')
      .insert([{
        name: name,
        email: email.toLowerCase(),
        password: hashed,
        role: role || 'User',
        department: department || 'General',
        status: 'Active',
        mfa: true
      }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(mapUser(data));
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// update a user (name, email, role, department, status, mfa, password)
router.put('/:id', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const id = req.params.id;
    var updates = {};
    if (req.body.name) updates.name = req.body.name;
    if (req.body.email) updates.email = req.body.email.toLowerCase();
    if (req.body.role) updates.role = req.body.role;
    if (req.body.department) updates.department = req.body.department;
    if (req.body.status) updates.status = req.body.status;
    if (typeof req.body.mfa === 'boolean') updates.mfa = req.body.mfa;

    // allow password change
    if (req.body.password) {
      updates.password = await bcrypt.hash(req.body.password, 10);
    }

    // nothing to update
    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    // if email changed, check it's not already taken by another user
    if (updates.email) {
      const { data: dup } = await supabase
        .from('users')
        .select('id')
        .eq('email', updates.email)
        .neq('id', id);
      if (dup && dup.length > 0) {
        return res.status(409).json({ error: 'Email already in use by another user' });
      }
    }

    const { data, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', id)
      .select()
      .single();

    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'User not found' });

    res.json(mapUser(data));
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// delete a user
router.delete('/:id', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const id = req.params.id;
    console.log('DELETE user id:', id);

    const { data, error } = await supabase
      .from('users')
      .delete()
      .eq('id', id)
      .select();

    console.log('DELETE result — data:', JSON.stringify(data), 'error:', error);

    if (error) throw error;
    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: 'User removed' });
  } catch (err) {
    console.error('DELETE error:', err);
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

module.exports = router;
