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
const SB_SERVICE_KEY = process.env.SB_SERVICE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'salpal-secret-change-this';
const PORT = process.env.PORT || 3000;

const SB_HEADERS = {
  'Content-Type': 'application/json',
  'apikey': SB_SERVICE_KEY,
  'Authorization': 'Bearer ' + SB_SERVICE_KEY,
  'Prefer': 'resolution=merge-duplicates,return=minimal'
};

// ── HELPERS ──
function mkId() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

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
  if (!r.ok) throw new Error(`sbUpsert ${table}/${id} failed: ${r.status}`);
  return r;
}

async function sbDelete(table, id) {
  const r = await fetch(`${SB_URL}/rest/v1/${table}?id=eq.${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: SB_HEADERS
  });
  return r;
}

// ── ATOMIC STOCK HELPERS ──
async function getStock(cls) {
  try {
    const key = 'stock__' + cls.replace(/[^a-zA-Z0-9]/g, '_');
    const r = await fetch(`${SB_URL}/rest/v1/sp_stock?id=eq.${encodeURIComponent(key)}&select=id,data`, { headers: SB_HEADERS });
    const rows = await r.json();
    if (rows && rows[0] && rows[0].data) return rows[0].data.qty || 0;
    // Fallback to __stock blob
    const r2 = await fetch(`${SB_URL}/rest/v1/sp_stock?id=eq.__stock&select=id,data`, { headers: SB_HEADERS });
    const rows2 = await r2.json();
    if (rows2 && rows2[0] && rows2[0].data) return rows2[0].data[cls] || 0;
    return 0;
  } catch(e) { return 0; }
}

async function saveStock(cls, qty) {
  const key = 'stock__' + cls.replace(/[^a-zA-Z0-9]/g, '_');
  await sbUpsert('sp_stock', key, { cls, qty, updatedAt: new Date().toISOString() });
}

async function saveLedger(entry) {
  await sbUpsert('sp_ledger', entry.id, entry);
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
    let ok = false;
    if (user.password && user.password.startsWith('$2')) {
      ok = await bcrypt.compare(password, user.password);
    } else {
      ok = password === user.password;
    }
    if (!ok) return res.status(401).json({ error: 'Invalid username or password' });
    if (!user.password || !user.password.startsWith('$2')) {
      user.password = await bcrypt.hash(password, 10);
      await sbUpsert('sp_users', user.id, user);
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, firstName: user.firstName, lastName: user.lastName },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    const { password: _, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (e) {
    console.error('login error', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── TOKEN REFRESH ──
app.post('/api/refresh', authMiddleware, (req, res) => {
  try {
    const token = jwt.sign(
      { id: req.user.id, username: req.user.username, role: req.user.role, firstName: req.user.firstName, lastName: req.user.lastName },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
    res.json({ token });
  } catch (e) {
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

    let filteredOrders = allOrders;
    let filteredCompanies = companies.map(r => r.data).filter(Boolean);
    let filteredRepairs = repairs.map(r => r.data).filter(Boolean);
    let filteredSortings = sortings.map(r => r.data).filter(Boolean);
    let filteredLedger = ledger.map(r => r.data).filter(Boolean);
    let filteredUsers = users.map(r => r.data).filter(Boolean);

    if (role === 'Driver') {
      const today = new Date().toISOString().slice(0, 10);
      filteredOrders = allOrders.filter(o => {
        if (o.driverId !== userId) return false;
        if (!['Completed', 'Pending Sort'].includes(o.status)) return true;
        return o.deliveryDate === today;
      });
      filteredCompanies = [];
      filteredRepairs = [];
      filteredSortings = [];
      filteredLedger = [];
      filteredUsers = [];
    } else if (role === 'Supervisor') {
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
      filteredOrders = allOrders.filter(o => {
        if (!['Completed', 'Pending Sort'].includes(o.status)) return true;
        const orderDate = (o.completedAt || o.updatedAt || o.deliveryDate || '').slice(0, 10);
        return orderDate >= sevenDaysAgo;
      });
      filteredUsers = filteredUsers.filter(u => ['Supervisor', 'Manager', 'Admin'].includes(u.role));
      filteredLedger = [];
    }

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

// ── ATOMIC REPAIR SAVE ──
app.post('/api/action/repair', authMiddleware, async (req, res) => {
  try {
    const { lines, src, supervisor, repairer, date } = req.body;
    if (!lines || !lines.length || !src || !supervisor || !repairer) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const now = date || new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedRepairs = [];
    const savedLedger = [];

    // Step 1: Save all repair records
    for (const line of lines) {
      const repair = {
        id: line.id || mkId(),
        supervisor,
        repairer,
        pallet_class: line.cls,
        src,
        qty: line.qty,
        date: now,
        _ledgerSynced: true
      };
      await sbUpsert('sp_repairs', repair.id, repair);
      savedRepairs.push(repair);
    }

    // Step 2: Update stock and create ledger entries for each output class
    const totalQty = lines.reduce((s, l) => s + l.qty, 0);
    for (const repair of savedRepairs) {
      const currentQty = await getStock(repair.pallet_class);
      const newQty = currentQty + repair.qty;
      await saveStock(repair.pallet_class, newQty);
      const ledgerEntry = {
        id: mkId(),
        date: now,
        type: 'Repair',
        ref: repair.id,
        cls: repair.pallet_class,
        dir: 'in',
        qty: repair.qty,
        balance: newQty,
        notes: `Repaired by ${repairer} from ${src}`,
        by
      };
      await saveLedger(ledgerEntry);
      savedLedger.push(ledgerEntry);
    }

    // Step 3: Deduct from defected source stock
    const srcCurrentQty = await getStock(src);
    const srcNewQty = srcCurrentQty - totalQty;
    await saveStock(src, srcNewQty);
    const srcLedger = {
      id: mkId(),
      date: now,
      type: 'Repair',
      ref: 'batch',
      cls: src,
      dir: 'out',
      qty: totalQty,
      balance: srcNewQty,
      notes: `Repaired → ${lines.map(l => `${l.qty}×${l.cls}`).join(', ')}`,
      by
    };
    await saveLedger(srcLedger);
    savedLedger.push(srcLedger);

    res.json({ ok: true, repairs: savedRepairs, ledger: savedLedger });
  } catch (e) {
    console.error('repair action error', e);
    res.status(500).json({ error: 'Failed to save repair: ' + e.message });
  }
});

// ── ATOMIC SORTING SAVE ──
app.post('/api/action/sorting', authMiddleware, async (req, res) => {
  try {
    const { pallets, supervisor, sorters, orderRef, date } = req.body;
    if (!pallets || !pallets.length || !supervisor || !sorters || !sorters.length) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if linked order is already completed — prevent double sorting
    if (orderRef) {
      const orderRows = await fetch(`${SB_URL}/rest/v1/sp_orders?id=eq.${encodeURIComponent(orderRef)}&select=id,data`, { headers: SB_HEADERS }).then(r=>r.json()).catch(()=>[]);
      // Also try finding by AWB
      const allOrders = await sbGet('sp_orders');
      const linkedOrder = allOrders.map(r=>r.data).filter(Boolean).find(o=>o.awb===orderRef);
      if (linkedOrder && linkedOrder.status === 'Completed') {
        return res.status(409).json({ error: `Order ${orderRef} is already Completed — cannot sort again` });
      }
    }

    const now = date || new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const totalQty = pallets.reduce((s, p) => s + p.qty, 0);
    const ledgerRef = orderRef || ('SRT-' + mkId().slice(0, 8).toUpperCase());

    const sorting = {
      id: mkId(),
      supervisor,
      sorters,
      pallets,
      totalQty,
      orderRef: orderRef || null,
      date: now,
      _ledgerSynced: true
    };

    // Step 1: Save sorting record
    await sbUpsert('sp_sortings', sorting.id, sorting);

    const savedLedger = [];

    // Step 2: Update stock for each output class and create ledger entries
    for (const p of pallets) {
      const currentQty = await getStock(p.cls);
      const newQty = currentQty + p.qty;
      await saveStock(p.cls, newQty);
      const entry = {
        id: mkId(),
        date: now,
        type: 'Sorting',
        ref: ledgerRef,
        cls: p.cls,
        dir: 'in',
        qty: p.qty,
        balance: newQty,
        notes: `Sorted by ${sorters.join(', ')}${orderRef ? ' · Order ' + orderRef : ''}`,
        by
      };
      await saveLedger(entry);
      savedLedger.push(entry);

      // Deduct from Unsorted
      const unsortedQty = await getStock('Unsorted');
      const newUnsorted = unsortedQty - p.qty;
      await saveStock('Unsorted', newUnsorted);
      const unsortedEntry = {
        id: mkId(),
        date: now,
        type: 'Sorting',
        ref: ledgerRef,
        cls: 'Unsorted',
        dir: 'out',
        qty: p.qty,
        balance: newUnsorted,
        notes: `Sorted → ${p.cls}${orderRef ? ' · Order ' + orderRef : ''}`,
        by
      };
      await saveLedger(unsortedEntry);
      savedLedger.push(unsortedEntry);
    }

    // Check if linked order is now fully sorted — auto-complete server-side
    let completedOrder = null;
    if (orderRef) {
      const allOrders = await sbGet('sp_orders');
      const linkedOrder = allOrders.map(r=>r.data).filter(Boolean).find(o=>o.awb===orderRef&&o.status==='Pending Sort');
      if (linkedOrder) {
        const orderedQty = (linkedOrder.pallets||[]).find(p=>p.cls==='Unsorted')?.qty || 0;
        // Get all sortings for this order from database
        const allSortings = await sbGet('sp_sortings');
        const existingSortings = allSortings.map(r=>r.data).filter(Boolean).filter(s=>s.orderRef===orderRef&&s.id!==sorting.id);
        const previouslySorted = existingSortings.reduce((s,r)=>s+(r.totalQty||0), 0);
        const totalNowSorted = previouslySorted + totalQty;
        if (totalNowSorted >= orderedQty) {
          linkedOrder.status = 'Completed';
          linkedOrder.completedAt = now;
          linkedOrder.updatedAt = now;
          await sbUpsert('sp_orders', linkedOrder.id, linkedOrder);
          completedOrder = linkedOrder;
        }
      }
    }

    res.json({ ok: true, sorting, ledger: savedLedger, completedOrder });
  } catch (e) {
    console.error('sorting action error', e);
    res.status(500).json({ error: 'Failed to save sorting: ' + e.message });
  }
});

// ── ATOMIC ORDER COMPLETE ──
app.post('/api/action/order/complete', authMiddleware, async (req, res) => {
  try {
    const { order } = req.body;
    if (!order || !order.id) return res.status(400).json({ error: 'Missing order' });

    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const now = new Date().toISOString();
    const savedLedger = [];

    // Update stock for each pallet
    for (const p of (order.pallets || [])) {
      if (!p.cls || !p.qty) continue;
      const currentQty = await getStock(p.cls);
      let newQty, dir, notes;

      if (order.type === 'Delivery') {
        newQty = currentQty - p.qty;
        dir = 'out';
        notes = `Delivered to ${order.companyName || ''}`;
      } else {
        newQty = currentQty + p.qty;
        dir = 'in';
        notes = `Received from ${order.companyName || ''}`;
      }

      await saveStock(p.cls, newQty);
      const entry = {
        id: mkId(),
        date: now,
        type: order.type === 'Delivery' ? 'Order Out' : 'Order In',
        ref: order.awb,
        cls: p.cls,
        dir,
        qty: p.qty,
        balance: newQty,
        notes,
        by
      };
      await saveLedger(entry);
      savedLedger.push(entry);
    }

    // Save completed order
    order.status = order.type === 'Delivery' ? 'Completed' : (order._hasPendingSort ? 'Pending Sort' : 'Completed');
    order.completedAt = now;
    order.updatedAt = now;
    await sbUpsert('sp_orders', order.id, order);

    res.json({ ok: true, order, ledger: savedLedger });
  } catch (e) {
    console.error('order complete error', e);
    res.status(500).json({ error: 'Failed to complete order: ' + e.message });
  }
});

// ── UPSERT (generic saves) ──
app.post('/api/upsert', authMiddleware, async (req, res) => {
  try {
    const { table, id, data } = req.body;
    if (!table || !id || !data) return res.status(400).json({ error: 'Missing fields' });
    if (table === 'sp_users' && req.user.role !== 'Admin' && req.user.role !== 'Manager') {
      return res.status(403).json({ error: 'Not allowed' });
    }
    if (table === 'sp_orders' && req.user.role === 'Driver') {
      if (data.driverId !== req.user.id) return res.status(403).json({ error: 'Not your order' });
    }
    // Preserve password when saving users
    if (table === 'sp_users' && !data.password) {
      try {
        const existing = await fetch(`${SB_URL}/rest/v1/sp_users?id=eq.${encodeURIComponent(id)}&select=id,data`, { headers: SB_HEADERS });
        const rows = await existing.json();
        if (rows && rows[0] && rows[0].data && rows[0].data.password) {
          data.password = rows[0].data.password;
        }
      } catch(e) { console.warn('Could not preserve password', e); }
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

// ── ATOMIC STOCK ADJUSTMENT ──
app.post('/api/action/adjustment', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { cls, qty, ref, note, by } = req.body;
    if (!cls || !qty) return res.status(400).json({ error: 'Missing fields' });

    const now = new Date().toISOString();
    const adjRef = ref || ('ADJ-' + mkId().slice(0, 6).toUpperCase());
    const byStr = by || `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const dir = qty > 0 ? 'in' : 'out';

    // Get current stock
    const currentQty = await getStock(cls);
    const newQty = currentQty + qty;

    // Save stock
    await saveStock(cls, newQty);

    // Save ledger
    const ledgerEntry = {
      id: mkId(),
      date: now,
      type: 'Manual Adjustment',
      ref: adjRef,
      cls,
      dir,
      qty: Math.abs(qty),
      balance: newQty,
      notes: note || (qty > 0 ? `Manual addition to ${cls}` : `Manual reduction of ${cls}`),
      by: byStr
    };
    await saveLedger(ledgerEntry);

    // Save adjustment record
    const adjustment = {
      id: mkId(),
      date: now,
      cls,
      qty,
      ref: adjRef,
      note: note || '',
      by: byStr
    };
    await sbUpsert('sp_stock', '__adj_' + adjustment.id, adjustment);

    res.json({ ok: true, ledger: ledgerEntry, adjustment, newQty });
  } catch (e) {
    console.error('adjustment error', e);
    res.status(500).json({ error: 'Failed to save adjustment: ' + e.message });
  }
});

// ── ATOMIC QUICK ENTRY (DISPATCH/RECEIVE) ──
app.post('/api/action/quickentry', authMiddleware, async (req, res) => {
  try {
    const { order, type } = req.body;
    if (!order || !type) return res.status(400).json({ error: 'Missing fields' });

    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];

    // Save order first
    order.createdAt = order.createdAt || now;
    order.updatedAt = now;
    await sbUpsert('sp_orders', order.id, order);

    // Update stock and create ledger entries
    for (const p of (order.pallets || [])) {
      if (!p.cls || !p.qty) continue;
      const currentQty = await getStock(p.cls);
      let newQty, dir, notes;
      if (type === 'Delivery') {
        newQty = currentQty - p.qty;
        dir = 'out';
        notes = `Quick dispatch to ${order.companyName || ''}`;
      } else {
        newQty = currentQty + p.qty;
        dir = 'in';
        notes = `Quick receive from ${order.companyName || ''}`;
      }
      await saveStock(p.cls, newQty);
      const entry = {
        id: mkId(), date: now,
        type: type === 'Delivery' ? 'Order Out' : 'Order In',
        ref: order.awb, cls: p.cls, dir, qty: p.qty, balance: newQty, notes, by
      };
      await saveLedger(entry);
      savedLedger.push(entry);
    }

    res.json({ ok: true, order, ledger: savedLedger });
  } catch (e) {
    console.error('quickentry error', e);
    res.status(500).json({ error: 'Failed to save: ' + e.message });
  }
});

// ── ATOMIC DELETE REPAIR (with stock reversal) ──
app.post('/api/action/repair/delete', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { repairId, pallet_class, src, qty } = req.body;
    if (!repairId || !pallet_class || !src || !qty) return res.status(400).json({ error: 'Missing fields' });

    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];

    // Reverse stock — remove repaired class
    const clsQty = await getStock(pallet_class);
    const newClsQty = clsQty - qty;
    await saveStock(pallet_class, newClsQty);
    const clsEntry = { id: mkId(), date: now, type: 'Repair Deleted', ref: repairId, cls: pallet_class, dir: 'out', qty, balance: newClsQty, notes: `Repair entry deleted`, by };
    await saveLedger(clsEntry);
    savedLedger.push(clsEntry);

    // Reverse stock — restore defected source
    const srcQty = await getStock(src);
    const newSrcQty = srcQty + qty;
    await saveStock(src, newSrcQty);
    const srcEntry = { id: mkId(), date: now, type: 'Repair Deleted', ref: repairId, cls: src, dir: 'in', qty, balance: newSrcQty, notes: `Restored from deleted repair`, by };
    await saveLedger(srcEntry);
    savedLedger.push(srcEntry);

    // Mark repair as deleted
    await sbUpsert('sp_repairs', repairId, { id: repairId, _deleted: true });

    res.json({ ok: true, ledger: savedLedger });
  } catch (e) {
    console.error('repair delete error', e);
    res.status(500).json({ error: 'Failed to delete repair: ' + e.message });
  }
});

// ── ATOMIC DELETE SORTING (with stock reversal) ──
app.post('/api/action/sorting/delete', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { sortingId, pallets, totalQty } = req.body;
    if (!sortingId || !pallets) return res.status(400).json({ error: 'Missing fields' });

    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];

    // Reverse each output class
    for (const p of pallets) {
      if (!p.cls || !p.qty) continue;
      const clsQty = await getStock(p.cls);
      const newClsQty = clsQty - p.qty;
      await saveStock(p.cls, newClsQty);
      const entry = { id: mkId(), date: now, type: 'Sorting Deleted', ref: sortingId, cls: p.cls, dir: 'out', qty: p.qty, balance: newClsQty, notes: `Sorting entry deleted`, by };
      await saveLedger(entry);
      savedLedger.push(entry);

      // Restore Unsorted
      const unsortedQty = await getStock('Unsorted');
      const newUnsorted = unsortedQty + p.qty;
      await saveStock('Unsorted', newUnsorted);
      const unsortedEntry = { id: mkId(), date: now, type: 'Sorting Deleted', ref: sortingId, cls: 'Unsorted', dir: 'in', qty: p.qty, balance: newUnsorted, notes: `Restored unsorted from deleted sorting`, by };
      await saveLedger(unsortedEntry);
      savedLedger.push(unsortedEntry);
    }

    // Mark sorting as deleted
    await sbUpsert('sp_sortings', sortingId, { id: sortingId, _deleted: true });

    res.json({ ok: true, ledger: savedLedger });
  } catch (e) {
    console.error('sorting delete error', e);
    res.status(500).json({ error: 'Failed to delete sorting: ' + e.message });
  }
});

// ── ATOMIC STOCKTAKE APPROVAL ──
app.post('/api/action/stocktake/approve', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { stocktake } = req.body;
    if (!stocktake || !stocktake.id) return res.status(400).json({ error: 'Missing stocktake' });

    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];

    // Apply each stock adjustment
    for (const c of (stocktake.counts || [])) {
      if (c.counted === null || c.counted === undefined) continue;
      const systemQty = await getStock(c.cls);
      const diff = c.counted - systemQty;
      if (diff === 0) continue;

      const newQty = systemQty + diff;
      await saveStock(c.cls, newQty);
      const entry = {
        id: mkId(), date: now, type: 'Stocktake',
        ref: stocktake.adjRef, cls: c.cls,
        dir: diff > 0 ? 'in' : 'out', qty: Math.abs(diff),
        balance: newQty,
        notes: `${stocktake.adjRef} — Stocktake by ${stocktake.userName || ''}`,
        by
      };
      await saveLedger(entry);
      savedLedger.push(entry);
    }

    // Update stocktake status
    stocktake.status = 'approved';
    stocktake.approvedAt = now;
    stocktake.approvedBy = by;
    await sbUpsert('sp_stocktakes', stocktake.id, stocktake);

    res.json({ ok: true, stocktake, ledger: savedLedger });
  } catch (e) {
    console.error('stocktake approve error', e);
    res.status(500).json({ error: 'Failed to approve stocktake: ' + e.message });
  }
});

// ── ATOMIC ORDER EDIT (pallet changes on completed orders) ──
app.post('/api/action/order/edit-pallets', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { order, oldPallets, newPallets } = req.body;
    if (!order || !oldPallets || !newPallets) return res.status(400).json({ error: 'Missing fields' });
    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];
    const editNote = `Admin edit on ${order.awb}`;
    if (order.type === 'Delivery') {
      for (const p of oldPallets) {
        if (!p.cls || !p.qty) continue;
        const qty = await getStock(p.cls); const newQty = qty + p.qty; await saveStock(p.cls, newQty);
        const e = {id:mkId(),date:now,type:'Order Edit',ref:order.awb,cls:p.cls,dir:'in',qty:p.qty,balance:newQty,notes:`Reversed old delivery — ${editNote}`,by};
        await saveLedger(e); savedLedger.push(e);
      }
      for (const p of newPallets) {
        if (!p.cls || !p.qty) continue;
        const qty = await getStock(p.cls); const newQty = qty - p.qty; await saveStock(p.cls, newQty);
        const e = {id:mkId(),date:now,type:'Order Edit',ref:order.awb,cls:p.cls,dir:'out',qty:p.qty,balance:newQty,notes:`New delivery pallet — ${editNote}`,by};
        await saveLedger(e); savedLedger.push(e);
      }
    } else {
      for (const p of oldPallets) {
        if (!p.cls || !p.qty) continue;
        const qty = await getStock(p.cls); const newQty = qty - p.qty; await saveStock(p.cls, newQty);
        const e = {id:mkId(),date:now,type:'Order Edit',ref:order.awb,cls:p.cls,dir:'out',qty:p.qty,balance:newQty,notes:`Reversed old collection — ${editNote}`,by};
        await saveLedger(e); savedLedger.push(e);
      }
      for (const p of newPallets) {
        if (!p.cls || !p.qty) continue;
        const qty = await getStock(p.cls); const newQty = qty + p.qty; await saveStock(p.cls, newQty);
        const e = {id:mkId(),date:now,type:'Order Edit',ref:order.awb,cls:p.cls,dir:'in',qty:p.qty,balance:newQty,notes:`New collection pallet — ${editNote}`,by};
        await saveLedger(e); savedLedger.push(e);
      }
    }
    await sbUpsert('sp_orders', order.id, order);
    res.json({ ok: true, ledger: savedLedger });
  } catch (e) { console.error('order edit-pallets error', e); res.status(500).json({ error: e.message }); }
});

// ── ATOMIC ORDER DELETE (with stock reversal) ──
app.post('/api/action/order/delete', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { order } = req.body;
    if (!order || !order.id) return res.status(400).json({ error: 'Missing order' });
    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];
    const stockMoved = ['Completed','Pending Sort','Loaded','In Transit','Collected','Delivered'];
    if (stockMoved.includes(order.status)) {
      for (const p of (order.pallets || [])) {
        if (!p.cls || !p.qty) continue;
        const currentQty = await getStock(p.cls);
        let newQty, dir, notes;
        if (order.type === 'Delivery') {
          newQty = currentQty + p.qty; dir = 'in';
          notes = `Deleted order — reversed delivery to ${order.companyName || ''}`;
        } else {
          newQty = currentQty - p.qty; dir = 'out';
          notes = `Deleted order — reversed collection from ${order.companyName || ''}`;
        }
        await saveStock(p.cls, newQty);
        const e = {id:mkId(),date:now,type:'Order Reversal',ref:order.awb,cls:p.cls,dir,qty:p.qty,balance:newQty,notes,by};
        await saveLedger(e); savedLedger.push(e);
      }
    }
    await sbDelete('sp_orders', order.id);
    res.json({ ok: true, ledger: savedLedger });
  } catch (e) { console.error('order delete error', e); res.status(500).json({ error: e.message }); }
});

// ── ATOMIC REPAIR EDIT ──
app.post('/api/action/repair/edit', authMiddleware, async (req, res) => {
  try {
    const { repair, oldCls, oldQty, oldSrc } = req.body;
    if (!repair || !oldCls) return res.status(400).json({ error: 'Missing fields' });
    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];
    const newCls = repair.pallet_class; const newQty = repair.qty; const newSrc = repair.src;
    if (oldCls !== newCls || oldQty !== newQty) {
      // Reverse old
      const oldClsQty = await getStock(oldCls); const newOldClsQty = oldClsQty - oldQty;
      await saveStock(oldCls, newOldClsQty);
      const e1 = {id:mkId(),date:now,type:'Repair Edit',ref:repair.id,cls:oldCls,dir:'out',qty:oldQty,balance:newOldClsQty,notes:`Repair edit — reversed old`,by};
      await saveLedger(e1); savedLedger.push(e1);
      const oldSrcQty = await getStock(oldSrc||oldCls); const newOldSrcQty = oldSrcQty + oldQty;
      await saveStock(oldSrc||oldCls, newOldSrcQty);
      const e2 = {id:mkId(),date:now,type:'Repair Edit',ref:repair.id,cls:oldSrc||oldCls,dir:'in',qty:oldQty,balance:newOldSrcQty,notes:`Repair edit — restored source`,by};
      await saveLedger(e2); savedLedger.push(e2);
      // Apply new
      const newClsQty = await getStock(newCls); const finalClsQty = newClsQty + newQty;
      await saveStock(newCls, finalClsQty);
      const e3 = {id:mkId(),date:now,type:'Repair Edit',ref:repair.id,cls:newCls,dir:'in',qty:newQty,balance:finalClsQty,notes:`Repair edit — new class`,by};
      await saveLedger(e3); savedLedger.push(e3);
      const newSrcQty = await getStock(newSrc||newCls); const finalSrcQty = newSrcQty - newQty;
      await saveStock(newSrc||newCls, finalSrcQty);
      const e4 = {id:mkId(),date:now,type:'Repair Edit',ref:repair.id,cls:newSrc||newCls,dir:'out',qty:newQty,balance:finalSrcQty,notes:`Repair edit — new source deduction`,by};
      await saveLedger(e4); savedLedger.push(e4);
    }
    await sbUpsert('sp_repairs', repair.id, repair);
    res.json({ ok: true, ledger: savedLedger });
  } catch (e) { console.error('repair edit error', e); res.status(500).json({ error: e.message }); }
});

// ── ATOMIC FIX STOCK ──
app.post('/api/action/fixstock', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { orderId, awb, pallets, type, companyName } = req.body;
    if (!orderId || !pallets) return res.status(400).json({ error: 'Missing fields' });
    const now = new Date().toISOString();
    const by = `${req.user.firstName || ''} ${req.user.lastName || ''}`.trim();
    const savedLedger = [];
    for (const p of pallets) {
      if (!p.cls || !p.qty) continue;
      const currentQty = await getStock(p.cls);
      let newQty, dir, notes;
      if (type === 'Delivery') {
        newQty = currentQty - p.qty; dir = 'out';
        notes = `Manual fix — Delivered to ${companyName || ''}`;
      } else {
        newQty = currentQty + p.qty; dir = 'in';
        notes = `Manual fix — Received from ${companyName || ''}`;
      }
      await saveStock(p.cls, newQty);
      const e = {id:mkId(),date:now,type:'Order Out',ref:awb,cls:p.cls,dir,qty:p.qty,balance:newQty,notes,by};
      await saveLedger(e); savedLedger.push(e);
    }
    res.json({ ok: true, ledger: savedLedger });
  } catch (e) { console.error('fixstock error', e); res.status(500).json({ error: e.message }); }
});
