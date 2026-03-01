// api/profile.js - Reflected XSS (harder: script tags stripped, must use event handlers)

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  let user = req.query.user || '';

  // HARDER: strips <script> tags but NOT event handlers
  // onerror=, onload=, onfocus= etc still work
  user = user.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '');
  user = user.replace(/<script/gi, '');

  return res.status(200).json({
    user,         // Still vulnerable via event handlers
    member_since: '2023',
    bio: null
  });
}