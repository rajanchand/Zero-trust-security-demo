require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// Supabase server client (use service_role key)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('SUPABASE_URL or SUPABASE_KEY missing in .env');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// make supabase available to routes
app.locals.supabase = supabase;

// middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// simple request logger
app.use(function (req, _res, next) {
  console.log(new Date().toISOString() + ' ' + req.method + ' ' + req.url);
  next();
});

// routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/users', require('./routes/users'));
app.use('/api/departments', require('./routes/departments'));

// global error handler
app.use(function (err, _req, res, _next) {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// start server
const PORT = process.env.PORT || 3000;

app.listen(PORT, function () {
  console.log('Server running on http://localhost:' + PORT);
});
