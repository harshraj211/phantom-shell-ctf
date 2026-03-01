// api/validate.js - Server-side flag validation only with encrypted token support.

import { FLAG_META, buildFlag, normalizeSubmittedFlag, fingerprintFlag } from './_flagSecurity.js';

const VALID_HASHES = Object.fromEntries(
  Object.entries(FLAG_META).map(([key, meta]) => {
    const digest = fingerprintFlag(buildFlag(key));
    return [digest, { key, points: meta.points }];
  })
);

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { flag } = req.body || {};
  const normalized = normalizeSubmittedFlag(flag);
  if (!normalized) return res.status(400).json({ valid: false });

  const digest = fingerprintFlag(normalized);
  const match = VALID_HASHES[digest];
  if (match) return res.status(200).json({ valid: true, key: match.key, points: match.points });
  return res.status(200).json({ valid: false });
}