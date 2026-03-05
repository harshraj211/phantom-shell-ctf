// api/profile.js - Reflected XSS (easy: script tags stripped, event handlers work)

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  let user = req.query.user || '';

  // EASY: strips <script> tags but NOT event handlers
  // Payloads that work: <img src=x onerror=alert(1)>
  user = user.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, '');
  user = user.replace(/<script/gi, '');

  return res.status(200).json({
    user,         // Still vulnerable via event handlers
    member_since: '2023',
    bio: null
  });
}