const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(cors({ origin: '*' }));

// ── ENV ──
const SB_URL = process.env.SB_URL;
const SB_SERVICE_KEY = process.env.SB_SERVICE_KEY; // service role key — never sent to browser
const JWT_SECRET = process.env.JWT_SECRET || 'salpal-secret-change-this';
const PORT = process.env.PORT || 3000;

const SB_HEADERS = {
  'Content-Type': 'application/json',
  'apikey': SB_SERVICE_KEY,
  'Authorization': 'Bearer ' + SB_SERVICE_KEY,
  'Prefer': 'resolution=merge-duplicates,return=minimal'
};

// ── SUPABASE HELPERS ──
async function sbGet(table) {
  const r = await fetch(`${SB_URL}/rest/v1/${table}?select=id,data`, { headers: SB_HEADERS });
  if (!r.ok) throw new Error(`sbGet ${table} failed: ${r.status}`);
  return r.json();
}

async function sbUpsert(table, id, data) {
  const r = await fetch(`${SB_URL}/rest/v1/${table}`, {
    method: 'POST',
    headers: SB_HEADERS,
    body: JSON.stringify({ id, data, updated_at: new Date().toISOString() })
  });
  if (!r.ok) throw new Error(`sbUpsert ${table} failed: ${r.status}`);
  return r;
}

async function sbDelete(table, id) {
  const r = await fetch(`${SB_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: SB_HEADERS
  });
  return r;
}

// ── AUTH MIDDLEWARE ──
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'Admin' && req.user.role !== 'Manager') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

    const rows = await sbGet('sp_users');
    const users = rows.map(r => r.data).filter(Boolean);
    const user = users.find(u => u.username && u.username.toLowerCase() === username.toLowerCase());

    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    // Check password — supports both bcrypt and plain text (migration)
    let ok = false;
    if (user.password && user.password.startsWith('$2')) {
      ok = await bcrypt.compare(password, user.password);
    } else {
      ok = password === user.password;
    }
    if (!ok) return res.status(401).json({ error: 'Invalid username or password' });

    // Auto-migrate plain text password to bcrypt
    if (!user.password.startsWith('$2')) {
      user.password = await bcrypt.hash(password, 10);
      await sbUpsert('sp_users', user.id, user);
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, firstName: user.firstName, lastName: user.lastName },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    // Return user without password
    const { password: _, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LOAD ALL DATA (role-filtered) ──
app.get('/api/data', authMiddleware, async (req, res) => {
  try {
    const role = req.user.role;
    const userId = req.user.id;

    const [orders, repairs, sortings, users, companies, ledger, stock, products, deleted, stocktakes] = await Promise.all([
      sbGet('sp_orders').catch(() => []),
      sbGet('sp_repairs').catch(() => []),
      sbGet('sp_sortings').catch(() => []),
      sbGet('sp_users').catch(() => []),
      sbGet('sp_companies').catch(() => []),
      sbGet('sp_ledger').catch(() => []),
      sbGet('sp_stock').catch(() => []),
      sbGet('sp_products').catch(() => []),
      sbGet('sp_deleted').catch(() => []),
      sbGet('sp_stocktakes').catch(() => [])
    ]);

    let allOrders = orders.map(r => r.data).filter(Boolean);
    const deletedIds = new Set(deleted.map(r => r.data).filter(Boolean).filter(e => e.type === 'order').map(e => e.originalId));
    allOrders = allOrders.filter(o => !deletedIds.has(o.id));

    // ── ROLE FILTERING ──
    let filteredOrders = allOrders;
    let filteredCompanies = companies.map(r => r.data).filter(Boolean);
    let filteredRepairs = repairs.map(r => r.data).filter(Boolean);
    let filteredSortings = sortings.map(r => r.data).filter(Boolean);
    let filteredLedger = ledger.map(r => r.data).filter(Boolean);
    let filteredUsers = users.map(r => r.data).filter(Boolean);

    if (role === 'Driver') {
      // Drivers only see their own orders for today and tomorrow
      const today = new Date().toISOString().slice(0, 10);
      const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
      filteredOrders = allOrders.filter(o =>
        o.driverId === userId &&
        o.deliveryDate >= today &&
        o.deliveryDate <= tomorrow &&
        !['Completed'].includes(o.status)
      );
      // Drivers see NO companies, ledger, repairs, sortings, users
      filteredCompanies = [];
      filteredRepairs = [];
      filteredSortings = [];
      filteredLedger = [];
      filteredUsers = [];
    } else if (role === 'Supervisor') {
      // Supervisors see last 7 days history
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
      filteredOrders = allOrders.filter(o => {
        if (!['Completed', 'Pending Sort'].includes(o.status)) return true;
        return (o.completedAt || o.updatedAt || '').slice(0, 10) >= sevenDaysAgo;
      });
      // Supervisors don't see user list or ledger
      filteredUsers = [];
      filteredLedger = [];
    }

    // Remove passwords from all user records
    filteredUsers = filteredUsers.map(({ password, ...u }) => u);

    res.json({
      orders: filteredOrders,
      repairs: filteredRepairs,
      sortings: filteredSortings,
      users: filteredUsers,
      companies: filteredCompanies,
      ledger: filteredLedger,
      stock: stock,
      products: products,
      deleted: deleted,
      stocktakes: stocktakes.map(r => r.data).filter(Boolean)
    });
  } catch (e) {
    console.error('data error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── UPSERT (write to Supabase) ──
app.post('/api/upsert', authMiddleware, async (req, res) => {
  try {
    const { table, id, data } = req.body;
    if (!table || !id || !data) return res.status(400).json({ error: 'Missing fields' });

    // Only admins can write to users table
    if (table === 'sp_users' && req.user.role !== 'Admin' && req.user.role !== 'Manager') {
      return res.status(403).json({ error: 'Not allowed' });
    }
    // Drivers can only update their own orders
    if (table === 'sp_orders' && req.user.role === 'Driver') {
      if (data.driverId !== req.user.id) {
        return res.status(403).json({ error: 'Not your order' });
      }
    }

    await sbUpsert(table, id, data);
    res.json({ ok: true });
  } catch (e) {
    console.error('upsert error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── DELETE ──
app.delete('/api/delete', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { table, id } = req.body;
    if (!table || !id) return res.status(400).json({ error: 'Missing fields' });
    await sbDelete(table, id);
    res.json({ ok: true });
  } catch (e) {
    console.error('delete error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── HEALTH CHECK ──
app.get('/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.listen(PORT, () => console.log(`SalPal API running on port ${PORT}`));
