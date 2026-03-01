// api/user.js - IDOR vulnerability
// IDOR: users can access any user's private data by changing the id parameter
// Flag is hidden in user id=5 private notes — not obvious at all

const USERS = [
  { id: 1, username: 'john',       email: 'john@example.com',    joined: '2023-01-10', orders: 12, notes: 'Nothing here.' },
  { id: 2, username: 'alice',      email: 'alice@example.com',   joined: '2023-03-22', orders: 5,  notes: 'Nothing here.' },
  { id: 3, username: 'bob',        email: 'bob@example.com',     joined: '2023-06-05', orders: 8,  notes: 'Nothing here.' },
  { id: 4, username: 'charlie',    email: 'charlie@example.com', joined: '2023-09-14', orders: 2,  notes: 'Nothing here.' },
  { id: 5, username: 'sysbackup',  email: 'backup@internal',     joined: '2022-01-01', orders: 0,  notes: 'FLAG{idor_peeking_at_private_data}' },
];

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  // Simulate logged-in user is id=1 (john)
  const currentUserId = 1;
  const requestedId = parseInt(req.query.id);

  if (isNaN(requestedId)) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  const user = USERS.find(u => u.id === requestedId);
  if (!user) return res.status(404).json({ error: 'User not found.' });

  // VULNERABLE: No authorization check — should verify requestedId === currentUserId
  // but it doesn't, so anyone can access any user's private notes
  return res.status(200).json({
    id: user.id,
    username: user.username,
    email: user.email,
    joined: user.joined,
    orders: user.orders,
    notes: user.notes   // Private field — should never be exposed to other users
  });
}