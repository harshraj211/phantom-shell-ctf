// api/profile.js - Intentionally vulnerable to Reflected XSS for CTF purposes

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  // VULNERABLE: returning raw user input without sanitization
  const user = req.query.user || '';

  return res.status(200).json({
    user: user, // RAW - intentional reflected XSS
    member_since: '2023',
    bio: null
  });
}