const express = require('express');
const router = express.Router();

// GET /api/policies — list all security policies
router.get('/', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { data, error } = await supabase
            .from('security_policies')
            .select('*')
            .order('policy_key', { ascending: true });

        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('Get policies error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/policies/:key — update a policy value
router.put('/:key', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { value, updatedBy } = req.body;

        if (value === undefined || value === null) {
            return res.status(400).json({ error: 'Value is required' });
        }

        const { data, error } = await supabase
            .from('security_policies')
            .update({
                policy_value: String(value),
                updated_by: updatedBy || 'Admin',
                updated_at: new Date().toISOString()
            })
            .eq('policy_key', req.params.key)
            .select('*')
            .single();

        if (error) throw error;
        if (!data) return res.status(404).json({ error: 'Policy not found' });

        res.json(data);
    } catch (err) {
        console.error('Update policy error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// helper: get a policy value by key (used by other routes)
async function getPolicy(supabase, key, defaultValue) {
    try {
        const { data } = await supabase
            .from('security_policies')
            .select('policy_value')
            .eq('policy_key', key)
            .single();

        return data ? data.policy_value : (defaultValue || null);
    } catch (err) {
        return defaultValue || null;
    }
}

module.exports = router;
module.exports.getPolicy = getPolicy;
