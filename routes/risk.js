// ============================================
// ZTS — Risk Score Engine
// NIST SP 800-207: Dynamic Trust Assessment
// ============================================
// Calculates risk based on: device trust, IP reputation,
// geo-location, failed logins, VPN detection, time-of-day
// Risk Levels: 0-30 Low, 31-60 Medium, 61-100 High

const express = require('express');
const router = express.Router();

// Risk factor weights (from NIST ZTA requirements)
const RISK_WEIGHTS = {
    NEW_DEVICE: 25,       // Unknown/unapproved device
    NEW_COUNTRY: 30,      // Login from new country
    FAILED_LOGINS: 20,    // Multiple failed login attempts
    VPN_DETECTED: 15,     // VPN/proxy detected
    ADMIN_UNKNOWN_IP: 35, // Admin login from unknown IP
    OFF_HOURS: 10,        // Login outside business hours
    IMPOSSIBLE_TRAVEL: 40 // Impossible travel detected
};

// Known VPN/proxy IP ranges (simulation)
const VPN_PATTERNS = ['10.8.', '10.9.', '172.16.', '100.64.'];

// Calculate risk score for a login attempt
function calculateRiskScore(opts) {
    var score = 0;
    var factors = [];

    // 1. New/unknown device (+25)
    if (!opts.deviceApproved) {
        score += RISK_WEIGHTS.NEW_DEVICE;
        factors.push({ factor: 'Unknown Device', points: RISK_WEIGHTS.NEW_DEVICE, detail: 'Device not registered or approved' });
    }

    // 2. New country (+30)
    if (opts.currentCountry && opts.lastCountry && opts.currentCountry !== opts.lastCountry) {
        score += RISK_WEIGHTS.NEW_COUNTRY;
        factors.push({ factor: 'New Country', points: RISK_WEIGHTS.NEW_COUNTRY, detail: 'Login from ' + opts.currentCountry + ' (last: ' + opts.lastCountry + ')' });
    } else if (!opts.lastCountry && opts.currentCountry) {
        // First login, no penalty but flag it
        factors.push({ factor: 'First Login Location', points: 0, detail: opts.currentCountry });
    }

    // 3. Failed login attempts (+20)
    if (opts.failedLogins >= 3) {
        score += RISK_WEIGHTS.FAILED_LOGINS;
        factors.push({ factor: 'Failed Logins', points: RISK_WEIGHTS.FAILED_LOGINS, detail: opts.failedLogins + ' failed attempts' });
    } else if (opts.failedLogins > 0) {
        var partial = Math.min(opts.failedLogins * 5, 15);
        score += partial;
        factors.push({ factor: 'Failed Logins', points: partial, detail: opts.failedLogins + ' failed attempts' });
    }

    // 4. VPN detected (+15)
    if (opts.vpnDetected) {
        score += RISK_WEIGHTS.VPN_DETECTED;
        factors.push({ factor: 'VPN Detected', points: RISK_WEIGHTS.VPN_DETECTED, detail: 'Connection via VPN/proxy' });
    }

    // 5. Admin from unknown IP (+35)
    if (opts.isAdmin && opts.ipChanged) {
        score += RISK_WEIGHTS.ADMIN_UNKNOWN_IP;
        factors.push({ factor: 'Admin Unknown IP', points: RISK_WEIGHTS.ADMIN_UNKNOWN_IP, detail: 'Admin login from new IP address' });
    }

    // 6. Off-hours access (+10)
    var hour = new Date().getUTCHours();
    if (hour < 6 || hour > 22) {
        score += RISK_WEIGHTS.OFF_HOURS;
        factors.push({ factor: 'Off-Hours', points: RISK_WEIGHTS.OFF_HOURS, detail: 'Login outside business hours' });
    }

    // 7. Impossible travel (+40)
    if (opts.impossibleTravel) {
        score += RISK_WEIGHTS.IMPOSSIBLE_TRAVEL;
        factors.push({ factor: 'Impossible Travel', points: RISK_WEIGHTS.IMPOSSIBLE_TRAVEL, detail: 'Location changed too quickly' });
    }

    // Clamp to 0-100
    score = Math.min(100, Math.max(0, score));

    var level = score <= 30 ? 'low' : score <= 60 ? 'medium' : 'high';

    return { score: score, level: level, factors: factors };
}

// Detect VPN from IP address (simulation)
function detectVPN(ip) {
    if (!ip) return false;
    for (var i = 0; i < VPN_PATTERNS.length; i++) {
        if (ip.indexOf(VPN_PATTERNS[i]) === 0) return true;
    }
    return false;
}

// Detect impossible travel: if user logged in from different country within 2 hours
function detectImpossibleTravel(lastLoginAt, lastCountry, currentCountry) {
    if (!lastLoginAt || !lastCountry || !currentCountry) return false;
    if (lastCountry === currentCountry) return false;
    var elapsed = Date.now() - new Date(lastLoginAt).getTime();
    var twoHours = 2 * 60 * 60 * 1000;
    return elapsed < twoHours;
}

// GET /api/risk/score/:userId — get user risk breakdown
router.get('/score/:userId', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data: user } = await supabase.from('users').select('*').eq('id', req.params.userId).single();
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Get latest login history  
        var { data: history } = await supabase
            .from('login_history')
            .select('*')
            .eq('user_id', req.params.userId)
            .order('created_at', { ascending: false })
            .limit(1);

        var latest = history && history.length > 0 ? history[0] : null;

        res.json({
            userId: user.id,
            email: user.email,
            currentScore: user.last_risk_score || 0,
            level: (user.last_risk_score || 0) <= 30 ? 'low' : (user.last_risk_score || 0) <= 60 ? 'medium' : 'high',
            factors: latest ? latest.risk_factors : [],
            lastLogin: user.last_login_at,
            lastCountry: user.last_country,
            lastIP: user.last_login_ip,
            failedAttempts: user.failed_login_count || 0
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/risk/history/:userId — risk score history
router.get('/history/:userId', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data } = await supabase
            .from('login_history')
            .select('risk_score, risk_level, created_at, ip_address, country, vpn_detected, is_suspicious')
            .eq('user_id', req.params.userId)
            .order('created_at', { ascending: false })
            .limit(50);

        res.json(data || []);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/risk/overview — admin risk overview
router.get('/overview', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        // Get all users with risk scores
        var { data: users } = await supabase.from('users').select('id, name, email, role, last_risk_score, failed_login_count, is_blocked');

        var low = 0, medium = 0, high = 0;
        var highRiskUsers = [];
        for (var i = 0; i < (users || []).length; i++) {
            var s = users[i].last_risk_score || 0;
            if (s <= 30) low++;
            else if (s <= 60) medium++;
            else { high++; highRiskUsers.push(users[i]); }
        }

        // Last 7 days login attempts
        var sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        var { data: logins } = await supabase
            .from('login_history')
            .select('created_at, login_success, risk_score')
            .gte('created_at', sevenDaysAgo)
            .order('created_at', { ascending: true });

        // Group by day
        var dailyData = {};
        for (var j = 0; j < (logins || []).length; j++) {
            var day = new Date(logins[j].created_at).toISOString().split('T')[0];
            if (!dailyData[day]) dailyData[day] = { total: 0, success: 0, failed: 0 };
            dailyData[day].total++;
            if (logins[j].login_success) dailyData[day].success++;
            else dailyData[day].failed++;
        }

        res.json({
            distribution: { low: low, medium: medium, high: high },
            highRiskUsers: highRiskUsers,
            dailyLogins: dailyData,
            totalUsers: (users || []).length
        });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/risk/login-history — all login history (admin)
router.get('/login-history', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data } = await supabase
            .from('login_history')
            .select('*')
            .order('created_at', { ascending: false })
            .limit(200);

        res.json(data || []);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/risk/suspicious — suspicious activities
router.get('/suspicious', async (req, res) => {
    var supabase = req.app.locals.supabase;
    try {
        var { data } = await supabase
            .from('login_history')
            .select('*')
            .eq('is_suspicious', true)
            .order('created_at', { ascending: false })
            .limit(100);

        res.json(data || []);
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
module.exports.calculateRiskScore = calculateRiskScore;
module.exports.detectVPN = detectVPN;
module.exports.detectImpossibleTravel = detectImpossibleTravel;
