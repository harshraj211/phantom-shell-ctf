// api/comment.js - Intentionally vulnerable to Stored XSS for CTF purposes
// Uses in-memory store (resets on cold start - fine for CTF demo)

// In-memory comment store
const comments = [
  {
    id: 1,
    name: 'Alice',
    comment: 'Great platform! Love the products here.',
    created_at: '2024-01-15 10:30:00'
  },
  {
    id: 2,
    name: 'Bob',
    comment: 'Has anyone tried the Gaming Keyboard? Worth it?',
    created_at: '2024-01-16 14:22:00'
  }
];

let nextId = 3;

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    // Return comments - RAW, unsanitized (intentionally vulnerable)
    return res.status(200).json({ comments });
  }

  if (req.method === 'POST') {
    const { name = 'Anonymous', comment = '' } = req.body || {};

    if (!comment.trim()) {
      return res.status(400).json({ error: 'Comment cannot be empty.' });
    }

    // VULNERABLE: storing raw unsanitized input
    const newComment = {
      id: nextId++,
      name: name.trim() || 'Anonymous',
      comment: comment, // NO sanitization - intentional for XSS CTF
      created_at: new Date().toISOString().replace('T', ' ').slice(0, 19)
    };

    comments.unshift(newComment);
    return res.status(200).json({ success: true, comment: newComment });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}