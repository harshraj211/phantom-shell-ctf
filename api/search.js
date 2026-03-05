// api/search.js - Intentionally vulnerable to UNION SQL Injection (easy version)

import { encryptFlagFromKey } from './_flagSecurity.js';

const PRODUCTS = [
  { id: 1, name: 'Laptop Pro X',    category: 'Electronics', price: 999.99 },
  { id: 2, name: 'Wireless Mouse',  category: 'Accessories', price: 29.99  },
  { id: 3, name: 'USB-C Hub',       category: 'Accessories', price: 49.99  },
  { id: 4, name: 'Gaming Keyboard', category: 'Accessories', price: 89.99  },
  { id: 5, name: 'Monitor 4K',      category: 'Electronics', price: 499.99 },
  { id: 6, name: 'Webcam HD',       category: 'Electronics', price: 79.99  },
  { id: 7, name: 'Desk Lamp',       category: 'Furniture',   price: 34.99  },
];

// EASY: column count is 4, table name is 'secrets'
// Payload: ' UNION SELECT 1,2,3,4 FROM secrets--

function vulnerableSearch(q) {
  const union = /union\s+select/i;
  if (!union.test(q)) {
    // Normal search
    const results = q
      ? PRODUCTS.filter(p => p.name.toLowerCase().includes(q.toLowerCase()))
      : PRODUCTS;
    return { results };
  }

  // Check if they used the correct table name
  if (/union\s+select\s+.+from\s+secrets/i.test(q)) {
    return {
      results: [{ id: '!', name: encryptFlagFromKey('union_select_ninja'), category: 'SECRET', price: 0 }]
    };
  }

  // Used UNION SELECT with a wrong table name
  if (/union\s+select\s+.+from\s+\w+/i.test(q)) {
    return {
      results: [{ id: '?', name: "Table not found. Hint: try 'secrets'.", category: '', price: null }]
    };
  }

  // UNION SELECT without FROM
  return {
    results: [{ id: '?', name: 'UNION detected! Add FROM <table_name> to extract data.', category: '', price: null }]
  };
}

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const q = req.query.q || '';
  const { results } = vulnerableSearch(q);
  return res.status(200).json({ results });
}