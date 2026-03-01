// api/search.js - Intentionally vulnerable to UNION SQL Injection (harder version)

const PRODUCTS = [
  { id: 1, name: 'Laptop Pro X',    category: 'Electronics', price: 999.99 },
  { id: 2, name: 'Wireless Mouse',  category: 'Accessories', price: 29.99  },
  { id: 3, name: 'USB-C Hub',       category: 'Accessories', price: 49.99  },
  { id: 4, name: 'Gaming Keyboard', category: 'Accessories', price: 89.99  },
  { id: 5, name: 'Monitor 4K',      category: 'Electronics', price: 499.99 },
  { id: 6, name: 'Webcam HD',       category: 'Electronics', price: 79.99  },
  { id: 7, name: 'Desk Lamp',       category: 'Furniture',   price: 34.99  },
];

// HARDER: column count is 4, but user must figure that out
// Table name is 'config' not 'secrets', column is 'value' not 'flag'
// Must also include WHERE key='flag' condition

function vulnerableSearch(q) {
  const union = /union\s+select/i;
  if (!union.test(q)) {
    // Normal search
    const results = q
      ? PRODUCTS.filter(p => p.name.toLowerCase().includes(q.toLowerCase()))
      : PRODUCTS;
    return { results };
  }

  // They found UNION — now check if they got the right table/column
  const correct = /union\s+select\s+.+from\s+config.+where\s+key\s*=\s*'flag'/i;
  const almostRight = /union\s+select\s+.+from\s+config/i;
  const wrongTable = /union\s+select\s+.+from\s+secrets/i;

  if (correct.test(q)) {
    return {
      results: [{ id: 1, name: 'FLAG{union_select_ninja}', category: 'config', price: null }]
    };
  }
  if (wrongTable.test(q)) {
    return {
      results: [{ id: '?', name: "Table 'secrets' doesn't exist.", category: '', price: null }]
    };
  }
  if (almostRight.test(q)) {
    return {
      results: [{ id: '?', name: 'Almost... check the WHERE clause.', category: 'config', price: null }]
    };
  }

  // Wrong column count or wrong syntax
  return {
    results: [{ id: '?', name: 'Column count mismatch. Try ORDER BY to find column count.', category: '', price: null }]
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