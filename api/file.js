// api/file.js - Path Traversal vulnerability
// Serves "static docs" but is vulnerable to directory traversal

import { encryptFlagFromKey } from './_flagSecurity.js';

const SAFE_FILES = {
  'readme.txt':   'Welcome to SecureShop documentation.',
  'terms.txt':    'Terms of service: Use at your own risk.',
  'help.txt':     'Contact support@secureshop.com for help.',
  'changelog.txt':'v1.0 - Initial release\nv1.1 - Bug fixes\nv1.2 - New products added',
};

// Simulated file system — traversal leads to secret directory
const SECRET_FILES = {
  'vault/cache.bin':     encryptFlagFromKey('path_traversal_master'),
  'vault/archive.dat':   encryptFlagFromKey('path_traversal_master'),
  'etc/passwd':          'root:x:0:0:root:/root:/bin/bash\njohn:x:1001:1001::/home/john:/bin/sh',
  'etc/shadow':          'Access denied.',
  'app/config.env':      'DB_HOST=localhost\nDB_PASS=hunter2\n# audit artifact stored in /vault/archive.dat',
};

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const name = req.query.name || '';
  if (!name) return res.status(400).json({ error: 'Missing ?name= parameter', available: Object.keys(SAFE_FILES) });

  // VULNERABLE: normalizes traversal sequences but does it WRONG
  // Only strips leading ../ but not encoded or nested versions
  // ....// and %2e%2e%2f and ..%2f all still work
  const cleaned = name
    .replace(/^(\.\.\/)+/, '')       // strips leading ../../../ 
    .replace(/%2f/gi, '/')            // decode %2f → /  (but then doesn't re-sanitize!)
    .replace(/%2e/gi, '.')            // decode %2e → .
    .replace(/\\/g, '/');             // normalize backslash

  // Re-check after decode — but misses ....// pattern
  if (cleaned.startsWith('../')) {
    return res.status(403).json({ error: 'Access denied.' });
  }

  // Check safe files first
  if (SAFE_FILES[cleaned]) {
    return res.status(200).json({ filename: cleaned, content: SAFE_FILES[cleaned] });
  }

  // VULNERABLE: traversal via ....// pattern bypasses the check above
  // e.g. ....//....//vault/archive.dat  →  after replace becomes  ../../vault/archive.dat
  // Simulate what the traversal resolves to
  const resolved = name
    .replace(/\.\.\.\.\//g, '../')    // ..../ → ../
    .replace(/%2e%2e%2f/gi, '../')    // %2e%2e%2f → ../
    .replace(/%2e%2e\//gi, '../')     // %2e%2e/ → ../
    .replace(/\.\.%2f/gi, '../')      // ..%2f → ../
    .replace(/\\/g, '/')
    .replace(/^[./]+/, '');           // strip leading slashes/dots

  if (SECRET_FILES[resolved]) {
    return res.status(200).json({ filename: resolved, content: SECRET_FILES[resolved] });
  }

  return res.status(404).json({ error: `File '${name}' not found.`, available: Object.keys(SAFE_FILES) });
}