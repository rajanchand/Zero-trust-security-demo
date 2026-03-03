const express = require('express');
const router = express.Router();
const { logEvent } = require('./audit');

// GET /api/devices — list all device approval requests (admin)
router.get('/', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { data, error } = await supabase
      .from('device_approvals')
      .select('*')
      .order('created_at', { ascending: false });

    if (error) throw error;

    res.json(data || []);
  } catch (err) {
    console.error('Get devices error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/devices/request — request device approval (after OTP verification)
router.post('/request', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { userId, userEmail, userName, ipAddress, geoLocation, deviceHealth, browser, os, fingerprint } = req.body;

    if (!userId || !userEmail || !fingerprint) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // check if this device is already approved for this user
    const { data: existing, error: findErr } = await supabase
      .from('device_approvals')
      .select('*')
      .eq('user_id', userId)
      .eq('fingerprint', fingerprint)
      .order('created_at', { ascending: false })
      .limit(1);

    if (findErr) throw findErr;

    if (existing && existing.length > 0) {
      var record = existing[0];

      if (record.status === 'Approved') {
        return res.json({ approved: true, message: 'Device already approved', device: record });
      }

      if (record.status === 'Pending') {
        // update device info (IP/geo may change)
        await supabase
          .from('device_approvals')
          .update({
            ip_address: ipAddress || record.ip_address,
            geo_location: geoLocation || record.geo_location,
            device_health: deviceHealth || record.device_health,
            browser: browser || record.browser,
            os: os || record.os
          })
          .eq('id', record.id);

        return res.json({ approved: false, message: 'Device approval pending', device: record });
      }

      if (record.status === 'Rejected') {
        // create a new request (allow re-request after rejection)
        var { data: newReq, error: newErr } = await supabase
          .from('device_approvals')
          .insert({
            user_id: userId,
            user_email: userEmail,
            user_name: userName || '',
            ip_address: ipAddress || '',
            geo_location: geoLocation || '',
            device_health: deviceHealth || 'Unknown',
            browser: browser || '',
            os: os || '',
            fingerprint: fingerprint,
            status: 'Pending',
            action: 'Awaiting Review'
          })
          .select('*')
          .single();

        if (newErr) throw newErr;
        return res.json({ approved: false, message: 'New device approval requested', device: newReq });
      }
    }

    // first time — create new request
    const { data: device, error: insertErr } = await supabase
      .from('device_approvals')
      .insert({
        user_id: userId,
        user_email: userEmail,
        user_name: userName || '',
        ip_address: ipAddress || '',
        geo_location: geoLocation || '',
        device_health: deviceHealth || 'Unknown',
        browser: browser || '',
        os: os || '',
        fingerprint: fingerprint,
        status: 'Pending',
        action: 'Awaiting Review'
      })
      .select('*')
      .single();

    if (insertErr) throw insertErr;

    res.json({ approved: false, message: 'Device approval requested', device: device });
  } catch (err) {
    console.error('Device request error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/devices/:id/approve — approve a device (admin)
router.put('/:id/approve', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { approvedBy } = req.body;

    const { data, error } = await supabase
      .from('device_approvals')
      .update({
        status: 'Approved',
        action: 'Approved',
        approved_by: approvedBy || 'Admin',
        approved_at: new Date().toISOString()
      })
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;

    await logEvent(supabase, {
      eventType: 'device_approved',
      severity: 'info',
      userEmail: data.user_email,
      details: 'Device approved by ' + (approvedBy || 'Admin') + ' — ' + data.browser
    });

    res.json({ message: 'Device approved', device: data });
  } catch (err) {
    console.error('Approve device error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/devices/:id/reject — reject a device (admin)
router.put('/:id/reject', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { approvedBy } = req.body;

    const { data, error } = await supabase
      .from('device_approvals')
      .update({
        status: 'Rejected',
        action: 'Rejected',
        approved_by: approvedBy || 'Admin',
        approved_at: new Date().toISOString()
      })
      .eq('id', req.params.id)
      .select('*')
      .single();

    if (error) throw error;

    await logEvent(supabase, {
      eventType: 'device_rejected',
      severity: 'warning',
      userEmail: data.user_email,
      details: 'Device rejected by ' + (approvedBy || 'Admin') + ' — ' + data.browser
    });

    res.json({ message: 'Device rejected', device: data });
  } catch (err) {
    console.error('Reject device error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/devices/:id — delete a device record (admin)
router.delete('/:id', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { error } = await supabase
      .from('device_approvals')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;

    res.json({ message: 'Device record deleted' });
  } catch (err) {
    console.error('Delete device error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/devices/check/:userId/:fingerprint — quick check if device is approved
router.get('/check/:userId/:fingerprint', async (req, res) => {
  const supabase = req.app.locals.supabase;
  try {
    const { data, error } = await supabase
      .from('device_approvals')
      .select('*')
      .eq('user_id', req.params.userId)
      .eq('fingerprint', req.params.fingerprint)
      .eq('status', 'Approved')
      .limit(1);

    if (error) throw error;

    res.json({ approved: data && data.length > 0 });
  } catch (err) {
    console.error('Check device error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
