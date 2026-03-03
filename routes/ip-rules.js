const express = require('express');
const router = express.Router();

// GET /api/ip-rules — list all IP rules
router.get('/', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { data, error } = await supabase
            .from('ip_rules')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) throw error;
        res.json(data || []);
    } catch (err) {
        console.error('Get IP rules error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/ip-rules — create a new IP rule
router.post('/', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { ip_pattern, rule_type, label, created_by } = req.body;

        if (!ip_pattern || !rule_type) {
            return res.status(400).json({ error: 'IP pattern and rule type are required' });
        }

        if (rule_type !== 'allow' && rule_type !== 'block') {
            return res.status(400).json({ error: 'Rule type must be "allow" or "block"' });
        }

        // check for duplicate
        const { data: existing } = await supabase
            .from('ip_rules')
            .select('id')
            .eq('ip_pattern', ip_pattern)
            .eq('rule_type', rule_type);

        if (existing && existing.length > 0) {
            return res.status(409).json({ error: 'This rule already exists' });
        }

        const { data, error } = await supabase
            .from('ip_rules')
            .insert({
                ip_pattern: ip_pattern,
                rule_type: rule_type,
                label: label || '',
                created_by: created_by || 'Admin'
            })
            .select('*')
            .single();

        if (error) throw error;
        res.status(201).json(data);
    } catch (err) {
        console.error('Create IP rule error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// DELETE /api/ip-rules/:id — delete an IP rule
router.delete('/:id', async (req, res) => {
    const supabase = req.app.locals.supabase;
    try {
        const { error } = await supabase
            .from('ip_rules')
            .delete()
            .eq('id', req.params.id);

        if (error) throw error;
        res.json({ message: 'IP rule deleted' });
    } catch (err) {
        console.error('Delete IP rule error:', err.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// helper: check IP against rules — returns { allowed: bool, reason: string }
async function checkIP(supabase, ipAddress) {
    try {
        // check if ip restriction is enabled
        const { data: policy } = await supabase
            .from('security_policies')
            .select('policy_value')
            .eq('policy_key', 'ip_restriction_enabled')
            .single();

        if (!policy || policy.policy_value !== 'true') {
            return { allowed: true, reason: 'IP restrictions disabled' };
        }

        const { data: rules } = await supabase
            .from('ip_rules')
            .select('*');

        if (!rules || rules.length === 0) {
            return { allowed: true, reason: 'No rules defined' };
        }

        // check blocked list first
        for (var i = 0; i < rules.length; i++) {
            if (rules[i].rule_type === 'block' && ipMatches(ipAddress, rules[i].ip_pattern)) {
                return { allowed: false, reason: 'IP is blocked: ' + rules[i].label };
            }
        }

        // check if there are any allow rules — if so, IP must match one
        var allowRules = rules.filter(function (r) { return r.rule_type === 'allow'; });
        if (allowRules.length > 0) {
            for (var j = 0; j < allowRules.length; j++) {
                if (ipMatches(ipAddress, allowRules[j].ip_pattern)) {
                    return { allowed: true, reason: 'IP is in allowlist' };
                }
            }
            return { allowed: false, reason: 'IP not in allowlist' };
        }

        return { allowed: true, reason: 'No block rule matched' };
    } catch (err) {
        console.error('IP check error:', err.message);
        return { allowed: true, reason: 'IP check failed — allowing by default' };
    }
}

// simple IP matching (exact match or wildcard prefix like 192.168.*)
function ipMatches(ip, pattern) {
    if (!ip || !pattern) return false;
    if (pattern === ip) return true;
    // wildcard matching: 192.168.* matches 192.168.1.1
    if (pattern.indexOf('*') > -1) {
        var prefix = pattern.replace(/\*/g, '');
        return ip.indexOf(prefix) === 0;
    }
    // CIDR not implemented — just exact + wildcard for now
    return false;
}

module.exports = router;
module.exports.checkIP = checkIP;
