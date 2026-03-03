// ============================================
// ZTS — Audit Log Routes
// NIST SP 800-207: Continuous Monitoring
// ============================================

const express = require('express');
const router = express.Router();

// Reusable audit log helper
async function logEvent(supabase, opts) {
    try {
        await supabase.from('audit_logs').insert({
            event_type: opts.eventType,
            severity: opts.severity || 'info',
            user_email: opts.userEmail || null,
            user_id: opts.userId || null,
            ip_address: opts.ipAddress || null,
            details: opts.details || '',
            metadata: opts.metadata || {}
        });
    } catch (e) { console.error('Audit log error:', e.message); }
}

// GET all audit logs (with optional severity filter)
router.get('/', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var query = supabase.from('audit_logs').select('*').order('created_at', { ascending: false }).limit(500);
        if (req.query.severity) query = query.eq('severity', req.query.severity);
        if (req.query.userEmail) query = query.eq('user_email', req.query.userEmail);
        var { data } = await query;
        res.json(data || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// GET audit stats (24h)
router.get('/stats', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        var { data } = await supabase.from('audit_logs').select('severity, created_at').gte('created_at', since);
        var info = 0, warning = 0, critical = 0;
        for (var i = 0; i < (data || []).length; i++) {
            if (data[i].severity === 'warning') warning++;
            else if (data[i].severity === 'critical') critical++;
            else info++;
        }
        res.json({ info: info, warning: warning, critical: critical, total: (data || []).length });
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// GET per-user audit trail
router.get('/user/:userId', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data } = await supabase.from('audit_logs').select('*').eq('user_id', req.params.userId).order('created_at', { ascending: false }).limit(100);
        res.json(data || []);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// GET daily stats for charts (last 7 days)
router.get('/daily', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        var { data } = await supabase.from('audit_logs').select('severity, created_at').gte('created_at', since);
        var daily = {};
        for (var i = 0; i < (data || []).length; i++) {
            var day = new Date(data[i].created_at).toISOString().split('T')[0];
            if (!daily[day]) daily[day] = { info: 0, warning: 0, critical: 0 };
            daily[day][data[i].severity] = (daily[day][data[i].severity] || 0) + 1;
        }
        res.json(daily);
    } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

module.exports = router;
module.exports.logEvent = logEvent;
