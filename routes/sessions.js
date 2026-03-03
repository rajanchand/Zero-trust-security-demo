// ============================================
// ZTS — Session Management Routes
// NIST SP 800-207: Continuous Session Validation
// ============================================

const express = require('express');
const router = express.Router();
const { logEvent } = require('./audit');

// GET all sessions
router.get('/', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data } = await supabase.from('sessions').select('*').order('created_at', { ascending: false }).limit(200);
        res.json(data || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// GET active session count
router.get('/active-count', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data } = await supabase.from('sessions').select('id').eq('is_active', true).gte('expires_at', new Date().toISOString());
        res.json({ count: (data || []).length });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// REVOKE session
router.put('/:id/revoke', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data, error } = await supabase.from('sessions')
            .update({ is_active: false, revoked_by: req.body.revokedBy || 'admin', revoked_at: new Date().toISOString() })
            .eq('id', req.params.id)
            .select('user_email').single();
        if (error) throw error;

        await logEvent(supabase, { eventType: 'session_revoked', severity: 'warning', userEmail: data.user_email, details: 'Revoked by ' + (req.body.revokedBy || 'admin') });

        res.json({ message: 'Session revoked' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// FORCE LOGOUT user (revoke all their sessions)
router.put('/force-logout/:userId', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data: user } = await supabase.from('users').select('email').eq('id', req.params.userId).single();

        await supabase.from('sessions')
            .update({ is_active: false, revoked_by: req.body.revokedBy || 'admin', revoked_at: new Date().toISOString() })
            .eq('user_id', req.params.userId)
            .eq('is_active', true);

        if (user) {
            await logEvent(supabase, { eventType: 'force_logout', severity: 'warning', userEmail: user.email, details: 'Force logged out by ' + (req.body.revokedBy || 'admin') });
        }

        res.json({ message: 'User force logged out' });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// CHECK session validity
router.get('/check/:sessionId', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data } = await supabase.from('sessions')
            .select('id, is_active, expires_at, revoked_by')
            .eq('id', req.params.sessionId).single();

        if (!data) return res.json({ valid: false, reason: 'Not found' });
        if (!data.is_active) return res.json({ valid: false, reason: data.revoked_by ? 'Revoked' : 'Inactive' });
        if (new Date(data.expires_at) <= new Date()) return res.json({ valid: false, reason: 'Expired' });

        res.json({ valid: true });
    } catch (err) { res.json({ valid: false }); }
});

module.exports = router;
