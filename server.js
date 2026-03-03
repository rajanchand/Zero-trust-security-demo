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

// in-memory OTP store: { email: { code, expiresAt, userId, name, role } }
app.locals.otpStore = new Map();

// auto-migrate: ensure phone and gender columns exist
async function runMigrations() {
  try {
    // try a quick select to see if columns exist already
    var { error } = await supabase.from('users').select('phone, gender').limit(1);
    if (!error) {
      console.log('✓ Database schema OK (phone, gender columns exist)');
      return;
    }

    console.log('⚙ Missing columns detected, attempting migration...');

    // try using the run_migration RPC function (created by migrate.sql)
    var { error: rpcErr } = await supabase.rpc('run_migration', {
      sql_text: "ALTER TABLE public.users ADD COLUMN IF NOT EXISTS phone text DEFAULT ''; ALTER TABLE public.users ADD COLUMN IF NOT EXISTS gender text DEFAULT '';"
    });

    if (!rpcErr) {
      console.log('✓ Migration successful — phone and gender columns added');
    } else {
      console.log('');
      console.log('⚠️  Could not auto-migrate. Please run migrate.sql in Supabase SQL Editor:');
      console.log('   1. Go to https://supabase.com/dashboard → SQL Editor');
      console.log('   2. Paste the contents of migrate.sql and click Run');
      console.log('   3. Restart this server');
      console.log('');
    }
  } catch (err) {
    console.log('⚠️  Migration check failed:', err.message);
  }
}

runMigrations();

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
app.use('/api/devices', require('./routes/devices'));

// global error handler
app.use(function (err, _req, res, _next) {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// start server
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, function () {
  console.log('Server running on http://' + HOST + ':' + PORT);
});
