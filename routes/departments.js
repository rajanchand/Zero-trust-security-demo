const express = require('express');
const router = express.Router();

// helper: map supabase row to front-end shape (id -> _id)
function mapDept(row) {
  return {
    _id: row.id,
    name: row.name,
    createdAt: row.created_at
  };
}

// get all departments
router.get('/', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { data, error } = await supabase
      .from('departments')
      .select('*')
      .order('name', { ascending: true });

    if (error) throw error;
    res.json(data.map(mapDept));
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// create a new department
router.post('/', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const name = req.body.name;

    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }

    // check if department already exists
    const { data: existing } = await supabase
      .from('departments')
      .select('id')
      .eq('name', name);

    if (existing && existing.length > 0) {
      return res.status(409).json({ error: 'Department already exists' });
    }

    const { data, error } = await supabase
      .from('departments')
      .insert([{ name: name }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(mapDept(data));
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

// delete a department
router.delete('/:id', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const id = req.params.id;
    const { data, error } = await supabase
      .from('departments')
      .delete()
      .eq('id', id)
      .select();

    if (error) throw error;
    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'Department not found' });
    }

    res.json({ message: 'Department removed' });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Server error' });
  }
});

module.exports = router;
