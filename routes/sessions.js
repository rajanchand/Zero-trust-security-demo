const express = require('express');
const router = express.Router();

// GET /api/sessions — list all active sessions (admin)
router.get('/', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        // clean up expired sessions first
        await supabase
            .from('sessions')
            .update({ is_active: false })
            .lt('expires_at', new Date().toISOString())
            .eq('is_active', true);

        const { data, error } = await supabase
            .from('sessions')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(100);

        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('Get sessions error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/sessions — create a new session
router.post('/', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { userId, userEmail, userName, ipAddress, browser, os, fingerprint, geoLocation, timeoutMinutes } = req.body;

        var expiresAt = new Date(Date.now() + (timeoutMinutes || 30) * 60 * 1000).toISOString();

        const { data, error } = await supabase
            .from('sessions')
            .insert({
                user_id: userId,
                user_email: userEmail,
                user_name: userName || '',
                ip_address: ipAddress || '',
                browser: browser || '',
                os: os || '',
                fingerprint: fingerprint || '',
                geo_location: geoLocation || '',
                expires_at: expiresAt,
                is_active: true
            })
            .select('*')
            .single();

        if (error) throw error;
        res.json(data);
    } catch (err) {
        console.error('Create session error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/sessions/check/:sessionId — check if session is still valid
router.get('/check/:sessionId', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { data, error } = await supabase
            .from('sessions')
            .select('*')
            .eq('id', req.params.sessionId)
            .single();

        if (error || !data) {
            return res.json({ valid: false, reason: 'Session not found' });
        }

        if (!data.is_active) {
            return res.json({ valid: false, reason: 'Session revoked' });
        }

        if (new Date(data.expires_at) < new Date()) {
            // mark as inactive
            await supabase.from('sessions').update({ is_active: false }).eq('id', data.id);
            return res.json({ valid: false, reason: 'Session expired' });
        }

        res.json({
            valid: true,
            expiresAt: data.expires_at,
            remainingMs: new Date(data.expires_at).getTime() - Date.now()
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/sessions/:id/revoke — admin revoke a session
router.put('/:id/revoke', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { revokedBy } = req.body;

        const { data, error } = await supabase
            .from('sessions')
            .update({
                is_active: false,
                revoked_by: revokedBy || 'Admin',
                revoked_at: new Date().toISOString()
            })
            .eq('id', req.params.id)
            .select('*')
            .single();

        if (error) throw error;
        res.json({ message: 'Session revoked', session: data });
    } catch (err) {
        console.error('Revoke session error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/sessions/active-count — count of active sessions
router.get('/active-count', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { data, error } = await supabase
            .from('sessions')
            .select('id')
            .eq('is_active', true)
            .gt('expires_at', new Date().toISOString());

        if (error) throw error;
        res.json({ count: (data || []).length });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
