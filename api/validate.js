// api/validate.js - Server-side flag validation only. Zero flags exposed to frontend.

const VALID_FLAGS = {
  'FLAG{js_source_hunter}':              { key: 'js_source_hunter',              points: 100 },
  'FLAG{sql_bypass_master}':             { key: 'sql_bypass_master',              points: 300 },
  'FLAG{union_select_ninja}':            { key: 'union_select_ninja',             points: 400 },
  'FLAG{xss_stored_pwned}':              { key: 'xss_stored_pwned',               points: 300 },
  'FLAG{xss_reflected_gotcha}':          { key: 'xss_reflected_gotcha',           points: 250 },
  'FLAG{idor_peeking_at_private_data}':  { key: 'idor_peeking_at_private_data',   points: 350 },
  'FLAG{path_traversal_master}':         { key: 'path_traversal_master',          points: 400 },
};

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { flag } = req.body || {};
  if (!flag) return res.status(400).json({ valid: false });

  const match = VALID_FLAGS[flag.trim()];
  if (match) return res.status(200).json({ valid: true, key: match.key, points: match.points });
  return res.status(200).json({ valid: false });
}