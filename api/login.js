// api/login.js - Intentionally vulnerable to SQL Injection for CTF purposes

const DB = {
  users: [
    { id: 1, username: 'admin',  password: 'supersecret123', role: 'admin' },
    { id: 2, username: 'john',   password: 'john1234',       role: 'user'  },
    { id: 3, username: 'alice',  password: 'alice5678',      role: 'user'  },
  ]
};

// Simulates a vulnerable SQL query by mimicking SQL injection behavior
function vulnerableQuery(username, password) {
  // Simulate: SELECT * FROM users WHERE username = '$username' AND password = '$password'
  // These payloads bypass auth just like real SQLi
  const bypassPatterns = [
    /'\s*or\s*'1'\s*=\s*'1/i,
    /'\s*or\s*1\s*=\s*1/i,
    /'\s*--/i,
    /'\s*#/i,
    /'\s*\/\*/i,
    /admin'\s*--/i,
    /'\s*or\s*'.*'\s*=\s*'/i,
  ];

  const isBypass = bypassPatterns.some(p => p.test(username) || p.test(password));

  if (isBypass) {
    // Return admin user like real SQLi bypass would
    return DB.users[0];
  }

  // Normal lookup
  return DB.users.find(u => u.username === username && u.password === password) || null;
}

export default function handler(req, res) {
  // Allow CORS for local dev
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { username = '', password = '' } = req.body || {};

  const user = vulnerableQuery(username, password);

  if (user) {
    const flag = user.role === 'admin'
      ? 'FLAG{sql_bypass_master}'
      : `FLAG{sql_login_user_${user.username.toLowerCase()}}`;

    return res.status(200).json({
      success: true,
      username: user.username,
      role: user.role,
      flag
    });
  }

  return res.status(401).json({ success: false, error: 'Invalid username or password.' });
}