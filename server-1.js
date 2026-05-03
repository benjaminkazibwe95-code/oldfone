require('dotenv').config();
const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const cron = require('node-cron');
const path = require('path');
const { makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const pino = require('pino');

const app = express();
const PORT = process.env.PORT || 3000;

// ── DATABASE ──────────────────────────────────────────────────────────────────
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plan TEXT DEFAULT 'free',
      plan_expires_at TIMESTAMPTZ,
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
  console.log('DB ready');

  // Always ensure admin is active
  if (process.env.ADMIN_EMAIL) {
    await db.query(
      "UPDATE users SET status='active', plan='pro' WHERE email=$1",
      [process.env.ADMIN_EMAIL.toLowerCase().trim()]
    );
  }
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // needed for HTML form POSTs

// Render is always HTTPS. trust proxy 1 makes req.secure = true correctly.
app.use(session({
  store: new pgSession({
    pool: db,
    tableName: 'user_sessions',
    createTableIfMissing: true  // auto-creates the sessions table in your DB
  }),
  secret: process.env.SESSION_SECRET || 'oldfone-secret-change-me',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: true,    // HTTPS only — correct for Render
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

// ── HELPERS ───────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}

function adminEmail() {
  return (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
}

async function checkIsAdmin(req) {
  if (!req.session.userId) return false;
  try {
    const r = await db.query('SELECT email FROM users WHERE id=$1', [req.session.userId]);
    return r.rows[0] && r.rows[0].email.toLowerCase() === adminEmail();
  } catch (e) { return false; }
}

// ── WHATSAPP ──────────────────────────────────────────────────────────────────
const activeSockets = {};

async function startWASession(userId, savedCreds) {
  const logger = pino({ level: 'silent' });
  const { version } = await fetchLatestBaileysVersion();
  let state, saveCreds;

  if (savedCreds) {
    const parsed = JSON.parse(savedCreds);
    state = { creds: parsed.creds, keys: parsed.keys || {} };
    saveCreds = async function() {
      const updated = JSON.stringify({ creds: state.creds, keys: state.keys });
      await db.query('UPDATE wa_sessions SET session_data=$1,last_seen=NOW() WHERE user_id=$2', [updated, userId]);
    };
  } else {
    const tmp = await useMultiFileAuthState('/tmp/wa_' + userId);
    state = tmp.state;
    saveCreds = tmp.saveCreds;
  }

  const sock = makeWASocket({ version, auth: state, logger, printQRInTerminal: false, browser: ['OldFone','Chrome','1.0'] });
  activeSockets[userId] = { sock, qr: null, status: 'connecting' };
  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async function(update) {
    const conn = update.connection;
    const qr = update.qr;
    const lastDisconnect = update.lastDisconnect;

    if (qr) {
      const img = await QRCode.toDataURL(qr);
      activeSockets[userId] = { sock: activeSockets[userId].sock, qr: img, status: 'awaiting_scan' };
    }
    if (conn === 'open') {
      const num = sock.user && sock.user.id ? sock.user.id.split(':')[0] : '';
      activeSockets[userId] = { sock, qr: null, status: 'connected' };
      const cj = JSON.stringify({ creds: state.creds, keys: state.keys || {} });
      await db.query(
        'INSERT INTO wa_sessions(user_id,session_data,wa_number,connected) VALUES($1,$2,$3,true) ON CONFLICT(user_id) DO UPDATE SET session_data=$2,wa_number=$3,connected=true,last_seen=NOW()',
        [userId, cj, num]
      );
      console.log('WA connected:', userId);
    }
    if (conn === 'close') {
      const code = lastDisconnect && lastDisconnect.error && lastDisconnect.error.output ? lastDisconnect.error.output.statusCode : 0;
      activeSockets[userId] = { sock, qr: null, status: 'disconnected' };
      await db.query('UPDATE wa_sessions SET connected=false WHERE user_id=$1', [userId]);
      if (code !== DisconnectReason.loggedOut) {
        setTimeout(function() { startWASession(userId, null); }, 5000);
      }
    }
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// HTML FORM ENDPOINTS — used by iPhone 6 Safari (no JS needed for login)
// These use normal form POST + redirect — 100% compatible with every browser
// ──────────────────────────────────────────────────────────────────────────────

app.post('/form/login', async function(req, res) {
  const email = (req.body.email || '').toLowerCase().trim();
  const password = req.body.password || '';
  try {
    const r = await db.query('SELECT * FROM users WHERE email=$1', [email]);
    const user = r.rows[0];
    if (!user) return res.redirect('/?err=notfound');
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.redirect('/?err=wrongpw');
    req.session.userId = user.id;
    req.session.save(function(err) {
      if (err) return res.redirect('/?err=session');
      if (email === adminEmail()) return res.redirect('/admin');
      return res.redirect('/dashboard');
    });
  } catch (e) {
    console.error(e);
    res.redirect('/?err=server');
  }
});

app.post('/form/register', async function(req, res) {
  const email = (req.body.email || '').toLowerCase().trim();
  const password = req.body.password || '';
  if (!email || password.length < 6) return res.redirect('/?err=invalid');
  try {
    const isAdmin = email === adminEmail();
    const hash = await bcrypt.hash(password, 10);
    const r = await db.query(
      'INSERT INTO users(email,password_hash,status,plan) VALUES($1,$2,$3,$4) RETURNING id',
      [email, hash, isAdmin ? 'active' : 'pending', isAdmin ? 'pro' : 'free']
    );
    req.session.userId = r.rows[0].id;
    req.session.save(function(err) {
      if (err) return res.redirect('/?err=session');
      return res.redirect(isAdmin ? '/admin' : '/dashboard');
    });
  } catch (e) {
    if (e.code === '23505') return res.redirect('/?err=exists');
    console.error(e);
    res.redirect('/?err=server');
  }
});

app.post('/form/logout', function(req, res) {
  req.session.destroy(function() { res.redirect('/'); });
});

// ── JSON API (for dashboard JS that runs after page load — session is stable by then)
app.get('/api/me', requireAuth, async function(req, res) {
  try {
    const r = await db.query('SELECT id,email,plan,status FROM users WHERE id=$1', [req.session.userId]);
    const u = r.rows[0];
    if (!u) return res.json({ ok: false });
    const ws = await db.query('SELECT wa_number,connected FROM wa_sessions WHERE user_id=$1', [u.id]);
    const sock = activeSockets[u.id];
    res.json({
      ok: true,
      user: u,
      wa: ws.rows[0] || null,
      socketStatus: sock ? sock.status : 'none',
      isAdmin: u.email.toLowerCase() === adminEmail()
    });
  } catch (e) { res.json({ ok: false }); }
});

app.post('/api/wa/start', requireAuth, async function(req, res) {
  const userId = req.session.userId;
  try {
    const ur = await db.query('SELECT status FROM users WHERE id=$1', [userId]);
    if (!ur.rows[0] || ur.rows[0].status !== 'active')
      return res.json({ ok: false, error: 'Account not active yet. Complete payment first.' });
    if (activeSockets[userId] && activeSockets[userId].status === 'connected')
      return res.json({ ok: true, status: 'already_connected' });
    const sr = await db.query('SELECT session_data FROM wa_sessions WHERE user_id=$1', [userId]);
    const saved = sr.rows[0] ? sr.rows[0].session_data : null;
    await startWASession(userId, saved);
    res.json({ ok: true, status: 'starting' });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.get('/api/wa/qr', requireAuth, function(req, res) {
  const sock = activeSockets[req.session.userId];
  if (!sock) return res.json({ ok: false, status: 'not_started', qr: null });
  res.json({ ok: true, status: sock.status, qr: sock.qr || null });
});

app.post('/api/wa/send', requireAuth, async function(req, res) {
  const sock = activeSockets[req.session.userId];
  if (!sock || sock.status !== 'connected') return res.json({ ok: false, error: 'Not connected' });
  try {
    const to = req.body.to.includes('@') ? req.body.to : req.body.to + '@s.whatsapp.net';
    await sock.sock.sendMessage(to, { text: req.body.message });
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/payment/submit', requireAuth, async function(req, res) {
  const { momo_number, momo_name, network, plan, ref } = req.body;
  if (!momo_number || !network || !plan) return res.json({ ok: false, error: 'Missing fields' });
  const amount = plan === 'pro3' ? 18000 : 7000;
  try {
    await db.query(
      'INSERT INTO payments(user_id,amount,momo_number,momo_name,network,plan,ref) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [req.session.userId, amount, momo_number, momo_name || '', network, plan, ref || '']
    );
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: 'Error saving' }); }
});

app.get('/api/payment/status', requireAuth, async function(req, res) {
  try {
    const r = await db.query(
      'SELECT status,plan,created_at FROM payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',
      [req.session.userId]
    );
    res.json({ ok: true, payment: r.rows[0] || null });
  } catch (e) { res.json({ ok: true, payment: null }); }
});

// ── ADMIN API ─────────────────────────────────────────────────────────────────
app.get('/api/admin/stats', async function(req, res) {
  if (!await checkIsAdmin(req)) return res.status(403).json({ error: 'Forbidden' });
  const [u, a, p, rev] = await Promise.all([
    db.query('SELECT COUNT(*) FROM users'),
    db.query("SELECT COUNT(*) FROM users WHERE status='active'"),
    db.query("SELECT COUNT(*) FROM payments WHERE status='confirmed'"),
    db.query("SELECT COALESCE(SUM(amount),0) as t FROM payments WHERE status='confirmed'")
  ]);
  res.json({ ok: true, stats: { totalUsers: u.rows[0].count, activeUsers: a.rows[0].count, confirmedPayments: p.rows[0].count, revenueUGX: rev.rows[0].t } });
});

app.get('/api/admin/payments', async function(req, res) {
  if (!await checkIsAdmin(req)) return res.status(403).json({ error: 'Forbidden' });
  const r = await db.query("SELECT p.*,u.email FROM payments p JOIN users u ON u.id=p.user_id WHERE p.status='pending' ORDER BY p.created_at ASC");
  res.json({ ok: true, payments: r.rows });
});

app.post('/api/admin/confirm', async function(req, res) {
  if (!await checkIsAdmin(req)) return res.status(403).json({ error: 'Forbidden' });
  const { payment_id, user_id, plan } = req.body;
  const exp = plan === 'pro3' ? new Date(Date.now() + 90*24*60*60*1000) : null;
  try {
    await db.query("UPDATE payments SET status='confirmed' WHERE id=$1", [payment_id]);
    await db.query("UPDATE users SET status='active',plan=$1,plan_expires_at=$2 WHERE id=$3", [plan, exp, user_id]);
    res.json({ ok: true });
  } catch (e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/admin/reject', async function(req, res) {
  if (!await checkIsAdmin(req)) return res.status(403).json({ error: 'Forbidden' });
  await db.query("UPDATE payments SET status='rejected' WHERE id=$1", [req.body.payment_id]);
  res.json({ ok: true });
});

app.get('/api/admin/users', async function(req, res) {
  if (!await checkIsAdmin(req)) return res.status(403).json({ error: 'Forbidden' });
  const r = await db.query('SELECT id,email,plan,status,created_at FROM users ORDER BY created_at DESC LIMIT 200');
  res.json({ ok: true, users: r.rows });
});

// ── CRON ──────────────────────────────────────────────────────────────────────
cron.schedule('0 * * * *', async function() {
  await db.query("UPDATE users SET status='suspended' WHERE plan_expires_at IS NOT NULL AND plan_expires_at < NOW()");
});

// ──────────────────────────────────────────────────────────────────────────────
// PAGE ROUTES — MUST come before any static middleware
// HTML files live in /pages/ folder so express.static never serves them
// ──────────────────────────────────────────────────────────────────────────────
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'pages', 'index.html'));
});

app.get('/dashboard', function(req, res) {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'pages', 'dashboard.html'));
});

app.get('/admin', async function(req, res) {
  if (!req.session.userId) return res.redirect('/');
  if (!await checkIsAdmin(req)) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'pages', 'admin.html'));
});

// Catch-all — redirect unknown paths to home
app.use(function(req, res) {
  res.redirect('/');
});

// ── START ─────────────────────────────────────────────────────────────────────
initDB().then(function() {
  app.listen(PORT, function() { console.log('OldFone running on port ' + PORT); });
});
