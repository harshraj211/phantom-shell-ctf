// api/login.js - Intentionally vulnerable to SQL Injection (harder version)

import { encryptFlagFromKey } from './_flagSecurity.js';

const DB = {
  users: [
    { id: 1, username: 'admin',   password: 'Adm!nS3cur3#2024', role: 'admin' },
    { id: 2, username: 'john',    password: 'j0hnP@ss!',         role: 'user'  },
    { id: 3, username: 'alice',   password: 'Al!ce$ecret',       role: 'user'  },
    { id: 4, username: 'bob',     password: 'B0bRules99',        role: 'user'  },
  ]
};

// Simulates: SELECT * FROM users WHERE username='$input' AND password='$input'
// HARDER: only comment-based bypass works now, OR '1'='1 style is filtered
function vulnerableQuery(username, password) {
  // Block naive OR bypass attempts
  const blocked = [/'.*or.*'1'.*=.*'1/i, /'\s*or\s*'\w+'\s*=\s*'\w+/i];
  if (blocked.some(p => p.test(username))) {
    return { error: 'Suspicious input detected.' };
  }

  // VULNERABLE: comment-based bypass still works
  // Payload: admin'-- or admin'#
  const commentBypass = /'\s*(--|#|\/\*)/;
  if (commentBypass.test(username)) {
    const uname = username.split("'")[0].trim();
    const user = DB.users.find(u => u.username === uname);
    if (user) return { user };
    // If username before ' doesn't match, still bypass as admin
    return { user: DB.users[0] };
  }

  // Normal login
  const user = DB.users.find(u => u.username === username && u.password === password);
  return user ? { user } : { error: 'Invalid credentials.' };
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { username = '', password = '' } = req.body || {};
  const result = vulnerableQuery(username, password);

  if (result.error) return res.status(401).json({ success: false, error: result.error });

  const { user } = result;
  return res.status(200).json({
    success: true,
    username: user.username,
    role: user.role,
    flagToken: user.role === 'admin' ? encryptFlagFromKey('sql_bypass_master') : null,
    message: user.role === 'admin' ? 'Welcome back, Admin.' : `Welcome, ${user.username}.`
  });
}