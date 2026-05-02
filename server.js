require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const cron = require('node-cron');
const path = require('path');
const { makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const pino = require('pino');

const app = express();
const PORT = process.env.PORT || 3000;

// ── DATABASE ──────────────────────────────────────────────────────────────────
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      phone TEXT,
      plan TEXT DEFAULT 'free',
      plan_expires_at TIMESTAMPTZ,
      momo_name TEXT,
      momo_ref TEXT,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wa_sessions (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      session_data TEXT,
      wa_number TEXT,
      connected BOOLEAN DEFAULT FALSE,
      last_seen TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id),
      amount INTEGER NOT NULL,
      momo_number TEXT NOT NULL,
      momo_name TEXT,
      network TEXT NOT NULL,
      plan TEXT NOT NULL,
      ref TEXT,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Database ready');

  // Auto-activate the admin account so you can use it immediately
  if (process.env.ADMIN_EMAIL) {
    await db.query(`
      UPDATE users SET status='active', plan='pro'
      WHERE email=$1 AND status='pending'
    `, [process.env.ADMIN_EMAIL.toLowerCase().trim()]);
  }
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve all HTML files from root directory (where you put them)
app.use(express.static(__dirname));

app.use(session({
  secret: process.env.SESSION_SECRET || 'oldfone-uganda-fallback-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ── ACTIVE WA SOCKETS ─────────────────────────────────────────────────────────
const activeSockets = {};

async function startWASession(userId, savedCreds) {
  const logger = pino({ level: 'silent' });
  const { version } = await fetchLatestBaileysVersion();

  let state, saveCreds;
  if (savedCreds) {
    const parsed = JSON.parse(savedCreds);
    state = { creds: parsed.creds, keys: parsed.keys || {} };
    saveCreds = async () => {
      const updated = JSON.stringify({ creds: state.creds, keys: state.keys });
      await db.query('UPDATE wa_sessions SET session_data=$1, last_seen=NOW() WHERE user_id=$2', [updated, userId]);
    };
  } else {
    const { state: s, saveCreds: sc } = await useMultiFileAuthState(`/tmp/wa_${userId}`);
    state = s;
    saveCreds = sc;
  }

  const sock = makeWASocket({
    version,
    auth: state,
    logger,
    printQRInTerminal: false,
    browser: ['OldFone', 'Chrome', '1.0']
  });
  activeSockets[userId] = { sock, qr: null, status: 'connecting' };

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      const qrImage = await QRCode.toDataURL(qr);
      activeSockets[userId] = { ...activeSockets[userId], qr: qrImage, status: 'awaiting_scan' };
    }

    if (connection === 'open') {
      const waNumber = sock.user?.id?.split(':')[0] || '';
      activeSockets[userId] = { ...activeSockets[userId], status: 'connected', qr: null };
      const credsJson = JSON.stringify({ creds: state.creds, keys: state.keys || {} });
      await db.query(`
        INSERT INTO wa_sessions (user_id, session_data, wa_number, connected)
        VALUES ($1,$2,$3,true)
        ON CONFLICT (user_id) DO UPDATE
        SET session_data=$2, wa_number=$3, connected=true, last_seen=NOW()
      `, [userId, credsJson, waNumber]);
      console.log('✅ WA connected for user', userId);
    }

    if (connection === 'close') {
      const reason = lastDisconnect?.error?.output?.statusCode;
      activeSockets[userId] = { ...activeSockets[userId], status: 'disconnected' };
      await db.query('UPDATE wa_sessions SET connected=false WHERE user_id=$1', [userId]);
      if (reason !== DisconnectReason.loggedOut) {
        console.log('🔄 Reconnecting user', userId);
        setTimeout(() => startWASession(userId, null), 5000);
      }
    }
  });

  return sock;
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6)
    return res.json({ ok: false, error: 'Email and password (6+ chars) required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const isAdmin = email.toLowerCase().trim() === (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
    const result = await db.query(
      `INSERT INTO users (email, password_hash, status, plan)
       VALUES ($1,$2,$3,$4)
       RETURNING id, email, plan, status`,
      [
        email.toLowerCase().trim(),
        hash,
        isAdmin ? 'active' : 'pending',
        isAdmin ? 'pro' : 'free'
      ]
    );
    const user = result.rows[0];
    req.session.userId = user.id;
    req.session.role = isAdmin ? 'admin' : 'user';
    res.json({ ok: true, user: { email: user.email, plan: user.plan, status: user.status }, isAdmin });
  } catch (e) {
    if (e.code === '23505') return res.json({ ok: false, error: 'Email already registered' });
    console.error(e);
    res.json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = result.rows[0];
    if (!user) return res.json({ ok: false, error: 'Email not found' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ ok: false, error: 'Wrong password' });
    const isAdmin = email.toLowerCase().trim() === (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
    req.session.userId = user.id;
    req.session.role = isAdmin ? 'admin' : 'user';
    res.json({ ok: true, user: { email: user.email, plan: user.plan, status: user.status }, isAdmin });
  } catch (e) {
    console.error(e);
    res.json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const r = await db.query('SELECT id, email, plan, status, phone FROM users WHERE id=$1', [req.session.userId]);
  const u = r.rows[0];
  if (!u) return res.json({ ok: false });
  const ws = await db.query('SELECT wa_number, connected FROM wa_sessions WHERE user_id=$1', [u.id]);
  const socket = activeSockets[u.id];
  res.json({ ok: true, user: u, wa: ws.rows[0] || null, socketStatus: socket?.status || 'none' });
});

// ── ADMIN: activate any user directly ────────────────────────────────────────
app.post('/api/admin/activate-user', requireAdmin, async (req, res) => {
  const { email, plan } = req.body;
  try {
    await db.query(
      "UPDATE users SET status='active', plan=$1 WHERE email=$2",
      [plan || 'pro', email.toLowerCase().trim()]
    );
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// ── WHATSAPP ──────────────────────────────────────────────────────────────────
app.post('/api/wa/start', requireAuth, async (req, res) => {
  const userId = req.session.userId;
  const ur = await db.query('SELECT status FROM users WHERE id=$1', [userId]);
  if (ur.rows[0]?.status !== 'active')
    return res.json({ ok: false, error: 'Account not active. Please pay to activate.' });

  const sr = await db.query('SELECT session_data FROM wa_sessions WHERE user_id=$1', [userId]);
  const savedCreds = sr.rows[0]?.session_data || null;

  if (activeSockets[userId]?.status === 'connected')
    return res.json({ ok: true, status: 'already_connected' });

  await startWASession(userId, savedCreds);
  res.json({ ok: true, status: 'starting' });
});

app.get('/api/wa/qr', requireAuth, async (req, res) => {
  const socket = activeSockets[req.session.userId];
  if (!socket) return res.json({ ok: false, status: 'not_started' });
  res.json({ ok: true, status: socket.status, qr: socket.qr || null });
});

app.get('/api/wa/status', requireAuth, async (req, res) => {
  const socket = activeSockets[req.session.userId];
  res.json({ ok: true, status: socket?.status || 'none' });
});

app.post('/api/wa/send', requireAuth, async (req, res) => {
  const { to, message } = req.body;
  const socket = activeSockets[req.session.userId];
  if (!socket || socket.status !== 'connected')
    return res.json({ ok: false, error: 'Not connected' });
  try {
    const jid = to.includes('@') ? to : `${to}@s.whatsapp.net`;
    await socket.sock.sendMessage(jid, { text: message });
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// ── PAYMENTS ──────────────────────────────────────────────────────────────────
app.post('/api/payment/submit', requireAuth, async (req, res) => {
  const { momo_number, momo_name, network, plan, ref } = req.body;
  const amount = plan === 'pro3' ? 18000 : 7000;
  try {
    await db.query(
      'INSERT INTO payments (user_id, amount, momo_number, momo_name, network, plan, ref) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [req.session.userId, amount, momo_number, momo_name, network, plan, ref]
    );
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: 'Error saving payment' });
  }
});

app.get('/api/payment/status', requireAuth, async (req, res) => {
  const r = await db.query(
    'SELECT status, plan, created_at FROM payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',
    [req.session.userId]
  );
  res.json({ ok: true, payment: r.rows[0] || null });
});

// ── ADMIN ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/payments', requireAdmin, async (req, res) => {
  const r = await db.query(`
    SELECT p.*, u.email FROM payments p
    JOIN users u ON u.id = p.user_id
    WHERE p.status = 'pending' ORDER BY p.created_at ASC
  `);
  res.json({ ok: true, payments: r.rows });
});

app.post('/api/admin/confirm-payment', requireAdmin, async (req, res) => {
  const { payment_id, user_id, plan } = req.body;
  const expiresAt = plan === 'pro3' ? new Date(Date.now() + 90 * 24 * 60 * 60 * 1000) : null;
  try {
    await db.query("UPDATE payments SET status='confirmed' WHERE id=$1", [payment_id]);
    await db.query(
      "UPDATE users SET status='active', plan=$1, plan_expires_at=$2 WHERE id=$3",
      [plan, expiresAt, user_id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

app.post('/api/admin/reject-payment', requireAdmin, async (req, res) => {
  await db.query("UPDATE payments SET status='rejected' WHERE id=$1", [req.body.payment_id]);
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const r = await db.query('SELECT id, email, plan, status, created_at FROM users ORDER BY created_at DESC LIMIT 200');
  res.json({ ok: true, users: r.rows });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [users, active, payments, revenue] = await Promise.all([
    db.query('SELECT COUNT(*) FROM users'),
    db.query("SELECT COUNT(*) FROM users WHERE status='active'"),
    db.query("SELECT COUNT(*) FROM payments WHERE status='confirmed'"),
    db.query("SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='confirmed'")
  ]);
  res.json({
    ok: true,
    stats: {
      totalUsers: users.rows[0].count,
      activeUsers: active.rows[0].count,
      confirmedPayments: payments.rows[0].count,
      revenueUGX: revenue.rows[0].total
    }
  });
});

// ── CRON ──────────────────────────────────────────────────────────────────────
cron.schedule('0 * * * *', async () => {
  await db.query(`
    UPDATE users SET status='suspended', plan='free'
    WHERE plan_expires_at IS NOT NULL AND plan_expires_at < NOW()
  `);
});

// ── PAGES ─────────────────────────────────────────────────────────────────────
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'dashboard.html'));
});
app.get('/admin', (req, res) => {
  if (req.session.role !== 'admin') return res.redirect('/');
  res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── START ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 OldFone running on port ${PORT}`));
});
