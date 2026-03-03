// ============================================
// ZTS — Device Trust Routes
// NIST SP 800-207: Device Verification
// ============================================

const express = require('express');
const router = express.Router();
const { logEvent } = require('./audit');

// GET all device approvals
router.get('/', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data } = await supabase.from('device_approvals').select('*').order('created_at', { ascending: false });
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// POST device request
router.post('/request', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { userId, userEmail, userName, ipAddress, geoLocation, deviceHealth, browser, os, fingerprint } = req.body;

    // Check existing device
    var { data: existing } = await supabase
      .from('device_approvals')
      .select('*')
      .eq('user_id', userId)
      .eq('fingerprint', fingerprint)
      .limit(1);

    if (existing && existing.length > 0) {
      var device = existing[0];
      if (device.status === 'Approved') return res.json({ approved: true, device: device });
      if (device.status === 'Pending') return res.json({ approved: false, device: device, message: 'Device pending approval' });

      // Rejected — create new request
      await supabase.from('device_approvals')
        .update({ status: 'Pending', ip_address: ipAddress, geo_location: geoLocation, device_health: deviceHealth, browser: browser, os: os })
        .eq('id', device.id);

      return res.json({ approved: false, message: 'Device re-submitted for approval' });
    }

    // New device
    var { data: newDev } = await supabase.from('device_approvals').insert({
      user_id: userId, user_email: userEmail, user_name: userName,
      ip_address: ipAddress, geo_location: geoLocation,
      device_health: deviceHealth, browser: browser, os: os,
      fingerprint: fingerprint, status: 'Pending'
    }).select('*').single();

    await logEvent(supabase, {
      eventType: 'device_request',
      severity: 'info',
      userEmail: userEmail,
      userId: userId,
      ipAddress: ipAddress,
      details: 'New device request: ' + browser + ' — ' + (deviceHealth || 'unknown health')
    });

    res.json({ approved: false, device: newDev, message: 'Device submitted for approval' });
  } catch (err) { res.status(500).json({ error: 'Device request failed' }); }
});

// CHECK device approval
router.get('/check/:userId/:fingerprint', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data } = await supabase
      .from('device_approvals')
      .select('status')
      .eq('user_id', req.params.userId)
      .eq('fingerprint', req.params.fingerprint)
      .eq('status', 'Approved')
      .limit(1);

    res.json({ approved: data && data.length > 0 });
  } catch (err) { res.json({ approved: false }); }
});

// APPROVE device
router.put('/:id/approve', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data } = await supabase.from('device_approvals')
      .update({ status: 'Approved', approved_by: req.body.approvedBy, approved_at: new Date().toISOString() })
      .eq('id', req.params.id).select('user_email').single();

    if (data) await logEvent(supabase, { eventType: 'device_approved', severity: 'info', userEmail: data.user_email, details: 'Approved by ' + req.body.approvedBy });

    res.json({ message: 'Device approved' });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// REJECT device
router.put('/:id/reject', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    var { data } = await supabase.from('device_approvals')
      .update({ status: 'Rejected', approved_by: req.body.approvedBy, approved_at: new Date().toISOString() })
      .eq('id', req.params.id).select('user_email').single();

    if (data) await logEvent(supabase, { eventType: 'device_rejected', severity: 'warning', userEmail: data.user_email, details: 'Rejected by ' + req.body.approvedBy });

    res.json({ message: 'Device rejected' });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// DELETE device
router.delete('/:id', async (req, res) => {
  var supabase = req.app.locals.supabase;
  try {
    await supabase.from('device_approvals').delete().eq('id', req.params.id);
    res.json({ message: 'Device deleted' });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

module.exports = router;
