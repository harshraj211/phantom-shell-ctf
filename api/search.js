// api/search.js - Intentionally vulnerable to UNION SQL Injection for CTF purposes

const PRODUCTS = [
  { id: 1, name: 'Laptop Pro X',    category: 'Electronics', price: 999.99 },
  { id: 2, name: 'Wireless Mouse',  category: 'Accessories', price: 29.99  },
  { id: 3, name: 'USB-C Hub',       category: 'Accessories', price: 49.99  },
  { id: 4, name: 'Gaming Keyboard', category: 'Accessories', price: 89.99  },
  { id: 5, name: 'Monitor 4K',      category: 'Electronics', price: 499.99 },
];

const SECRET_FLAG = 'FLAG{union_select_ninja}';

// Simulates: SELECT id,name,category,price FROM products WHERE name LIKE '%q%'
// Vulnerable to UNION injection
function vulnerableSearch(q) {
  // Detect UNION injection attempts
  const unionPattern = /union\s+select/i;

  if (unionPattern.test(q)) {
    // Simulate: ' UNION SELECT 1,flag,3,4 FROM secrets--
    // Extract what column they're injecting into
    const flagPattern = /union\s+select\s+[\d,\s]*flag[\d,\s]*/i;
    if (flagPattern.test(q) || /from\s+secrets/i.test(q)) {
      // Return the secret flag as if it came from the secrets table
      return {
        results: [{ id: 1, name: SECRET_FLAG, category: '-- secrets table --', price: null }],
        injected: true
      };
    }
    // Generic union - return partial result to hint they're on right track
    return {
      results: [{ id: '?', name: '-- try: UNION SELECT 1,flag,3,4 FROM secrets--', category: '', price: null }],
      injected: true
    };
  }

  // Normal search
  const results = PRODUCTS.filter(p =>
    p.name.toLowerCase().includes(q.toLowerCase())
  );
  return { results, injected: false };
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const q = req.query.q || '';

  if (!q) return res.status(200).json({ results: PRODUCTS });

  const { results, injected } = vulnerableSearch(q);
  return res.status(200).json({ results, injected });
}