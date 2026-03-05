// api/file.js - Path Traversal vulnerability
// Serves "static docs" but is vulnerable to directory traversal

import { encryptFlagFromKey } from './_flagSecurity.js';

const SAFE_FILES = {
  'readme.txt':   'Welcome to SecureShop documentation.',
  'terms.txt':    'Terms of service: Use at your own risk.',
  'help.txt':     'Contact support@secureshop.com for help.',
  'changelog.txt':'v1.0 - Initial release\nv1.1 - Bug fixes\nv1.2 - New products added\nv1.3 - Moved internal files to /vault/ directory',
};

// Simulated file system — traversal leads to secret directory
const SECRET_FILES = {
  'vault/cache.bin':     encryptFlagFromKey('path_traversal_master'),
  'vault/archive.dat':   encryptFlagFromKey('path_traversal_master'),
  'etc/passwd':          'root:x:0:0:root:/root:/bin/bash\njohn:x:1001:1001::/home/john:/bin/sh',
  'app/config.env':      'DB_HOST=localhost\nDB_PASS=hunter2\n# secret data stored in /vault/ directory',
};

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const name = req.query.name || '';
  if (!name) return res.status(400).json({ error: 'Missing ?name= parameter', available: Object.keys(SAFE_FILES) });

  // Check safe files first
  if (SAFE_FILES[name]) {
    return res.status(200).json({ filename: name, content: SAFE_FILES[name] });
  }

  // VULNERABLE: "sanitizes" ../ but the resolved path still accesses secret files
  // The server strips ../ prefixes but then looks up the remaining path in SECRET_FILES
  // e.g. ../vault/archive.dat → vault/archive.dat → found in SECRET_FILES!
  const hasTraversal = /\.\.\//;
  if (hasTraversal.test(name)) {
    const resolved = name
      .replace(/\\/g, '/')
      .replace(/^(\.\.\/)+/, '');     // strip leading ../../../

    if (SECRET_FILES[resolved]) {
      return res.status(200).json({ filename: resolved, content: SECRET_FILES[resolved] });
    }
  }

  return res.status(404).json({ error: `File '${name}' not found.`, available: Object.keys(SAFE_FILES) });
}