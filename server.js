require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
app.locals.supabase = supabase;
app.locals.otpStore = new Map();

// Middleware
app.use(cors());
app.use(express.json());

// Prevent browser caching
app.use(function (req, res, next) {
  if (req.url.endsWith('.html') || req.url.endsWith('.js') || req.url.endsWith('.css') || req.url === '/') {
    res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  }
  next();
});

// Serve static files
app.use(express.static(path.join(__dirname)));

// API Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/departments', require('./routes/departments'));
app.use('/api/devices', require('./routes/devices'));
app.use('/api/audit', require('./routes/audit'));
app.use('/api/sessions', require('./routes/sessions'));
app.use('/api/ip-rules', require('./routes/ip-rules'));
app.use('/api/policies', require('./routes/policies'));
app.use('/api/risk', require('./routes/risk'));

// Error handler
app.use(function (err, req, res, next) {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', function () {
  console.log('ZTS Server running on http://localhost:' + PORT);
});
