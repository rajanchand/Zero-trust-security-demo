const express = require('express');
const router = express.Router();

// helper: log a security event (used by other routes too)
async function logEvent(supabase, opts) {
    try {
        await supabase.from('audit_logs').insert({
            event_type: opts.eventType || 'unknown',
            severity: opts.severity || 'info',
            user_email: opts.userEmail || null,
            user_id: opts.userId || null,
            ip_address: opts.ipAddress || null,
            details: opts.details || '',
            metadata: opts.metadata || {}
        });
    } catch (err) {
        console.error('Audit log error:', err.message);
    }
}

// GET /api/audit — list audit logs (admin, with pagination and filters)
router.get('/', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        var query = supabase
            .from('audit_logs')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(200);

        // optional filters
        if (req.query.severity) {
            query = query.eq('severity', req.query.severity);
        }
        if (req.query.event_type) {
            query = query.eq('event_type', req.query.event_type);
        }
        if (req.query.user_email) {
            query = query.ilike('user_email', '%' + req.query.user_email + '%');
        }

        const { data, error } = await query;
        if (error) throw error;

        res.json(data || []);
    } catch (err) {
        console.error('Get audit logs error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/audit/stats — summary stats for dashboard
router.get('/stats', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { data, error } = await supabase
            .from('audit_logs')
            .select('severity')
            .gte('created_at', new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString());

        if (error) throw error;

        var stats = { total: 0, info: 0, warning: 0, critical: 0 };
        for (var i = 0; i < (data || []).length; i++) {
            stats.total++;
            if (data[i].severity === 'info') stats.info++;
            if (data[i].severity === 'warning') stats.warning++;
            if (data[i].severity === 'critical') stats.critical++;
        }

        res.json(stats);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
module.exports.logEvent = logEvent;
