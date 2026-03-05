import { encryptFlagFromKey } from './_flagSecurity.js';

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const key = String(req.query.key || '').trim();
  const ALLOWED_KEYS = ['js_source_hunter', 'xss_stored_pwned', 'xss_reflected_gotcha'];
  if (!ALLOWED_KEYS.includes(key)) {
    return res.status(404).json({ error: 'Unknown challenge key.' });
  }

  return res.status(200).json({ key, token: encryptFlagFromKey(key) });
}
