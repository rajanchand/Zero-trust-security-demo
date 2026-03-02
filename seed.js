require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const readline = require('readline');

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_KEY) {
  console.error('SUPABASE_URL or SUPABASE_KEY missing in .env');
  process.exit(1);
}

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

// default departments to create
var departmentNames = ['IT', 'HR', 'Finance', 'Operations', 'Security'];

// default users to create
var users = [
  {
    name: 'Rajan Chand',
    email: 'rajanchand48@gmail.com',
    password: 'Rajan33555@',
    role: 'Super Admin',
    department: 'IT',
    status: 'Active',
    mfa: true
  },
  {
    name: 'Support User',
    email: 'rajanthakuri1@gmail.com',
    password: 'Support33555@',
    role: 'User',
    department: 'HR',
    status: 'Active',
    mfa: true
  },
  {
    name: 'Alice Johnson',
    email: 'alice@example.com',
    password: 'Alice12345@',
    role: 'Admin',
    department: 'Finance',
    status: 'Active',
    mfa: true
  },
  {
    name: 'Bob Smith',
    email: 'bob@example.com',
    password: 'Bob12345@',
    role: 'Manager',
    department: 'Operations',
    status: 'Active',
    mfa: true
  },
  {
    name: 'Charlie Brown',
    email: 'charlie@example.com',
    password: 'Charlie12345@',
    role: 'Viewer',
    department: 'Security',
    status: 'Suspended',
    mfa: false
  }
];

// prompt for confirmation before wiping data
function askConfirmation(question) {
  return new Promise(function (resolve) {
    // if --yes flag is passed, skip prompt
    if (process.argv.includes('--yes') || process.argv.includes('-y')) {
      resolve(true);
      return;
    }
    var rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, function (answer) {
      rl.close();
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}

async function seed() {
  try {
    console.log('Connecting to Supabase...');
    console.log('URL: ' + process.env.SUPABASE_URL);

    var confirmed = await askConfirmation(
      '\n⚠️  This will DELETE all existing users and departments and re-create them.\n' +
      'Continue? (y/N): '
    );

    if (!confirmed) {
      console.log('Aborted.');
      process.exit(0);
    }

    // clear old data — delete where id is not null (all rows)
    var { error: delUsersErr } = await supabase.from('users').delete().not('id', 'is', null);
    if (delUsersErr) {
      console.error('Failed to clear users:', delUsersErr.message);
    }

    var { error: delDeptsErr } = await supabase.from('departments').delete().not('id', 'is', null);
    if (delDeptsErr) {
      console.error('Failed to clear departments:', delDeptsErr.message);
    }
    console.log('✓ Cleared old data');

    // create departments
    var deptErrors = 0;
    for (var i = 0; i < departmentNames.length; i++) {
      var { error } = await supabase.from('departments').insert([{ name: departmentNames[i] }]);
      if (error) {
        console.error('  ✗ Dept "' + departmentNames[i] + '": ' + error.message);
        deptErrors++;
      }
    }
    console.log('✓ Created ' + (departmentNames.length - deptErrors) + '/' + departmentNames.length + ' departments');

    // create users (hash passwords with bcrypt)
    var userErrors = 0;
    for (var j = 0; j < users.length; j++) {
      var hashed = await bcrypt.hash(users[j].password, 10);
      var { error: userErr } = await supabase.from('users').insert([{
        name: users[j].name,
        email: users[j].email.toLowerCase(),
        password: hashed,
        role: users[j].role,
        department: users[j].department,
        status: users[j].status,
        mfa: users[j].mfa
      }]);
      if (userErr) {
        console.error('  ✗ User "' + users[j].email + '": ' + userErr.message);
        userErrors++;
      }
    }
    console.log('✓ Created ' + (users.length - userErrors) + '/' + users.length + ' users');

    if (deptErrors + userErrors > 0) {
      console.log('\n⚠️  Seed completed with ' + (deptErrors + userErrors) + ' error(s). See above.');
    } else {
      console.log('\n✅ Seed complete — all data inserted successfully!');
    }

    process.exit(0);
  } catch (err) {
    console.error('Seed error:', err.message);
    process.exit(1);
  }
}

seed();
