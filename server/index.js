'use strict';

const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { rateLimit } = require('express-rate-limit');
const argon2 = require('argon2');
const { Pool } = require('pg');

const required = ['DATABASE_URL', 'SESSION_SECRET'];
for (const key of required) {
  if (!process.env[key]) throw new Error(`Missing required environment variable: ${key}`);
}
if (process.env.SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const port = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '32kb', type: 'application/json' }));
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    const contentType = req.get('content-type') || '';
    if (!contentType.toLowerCase().startsWith('application/json')) {
      return res.status(415).json({ error: 'Content-Type application/json richiesto' });
    }
    const origin = req.get('origin');
    const expectedOrigin = process.env.APP_ORIGIN;
    if (origin && expectedOrigin && origin !== expectedOrigin) {
      return res.status(403).json({ error: 'Origin non autorizzata' });
    }
  }
  next();
});

app.use(session({
  name: 'assetclient.sid',
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: production,
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Troppi tentativi. Riprova tra qualche minuto.' }
});

async function initialize() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin', 'operator')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS app_users_active_idx ON app_users(active);
  `);

  const username = String(process.env.BOOTSTRAP_ADMIN_USERNAME || '').trim();
  const password = String(process.env.BOOTSTRAP_ADMIN_PASSWORD || '');
  if (username && password) {
    if (username.length < 3 || username.length > 64 || password.length < 12) {
      throw new Error('Bootstrap admin: username deve avere 3-64 caratteri e password almeno 12');
    }
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    await pool.query(
      `INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,'admin')
       ON CONFLICT (username) DO NOTHING`,
      [username, hash]
    );
  }
}

function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role };
}
async function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Autenticazione richiesta' });
  try {
    const result = await pool.query(
      'SELECT id, username, role, active FROM app_users WHERE id=$1',
      [req.session.userId]
    );
    const user = result.rows[0];
    if (!user || !user.active) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'Sessione non valida' });
    }
    req.user = user;
    next();
  } catch (error) { next(error); }
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Permesso amministratore richiesto' });
  next();
}
function validUsername(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9._-]{3,64}$/.test(value);
}

app.get('/api/health', async (_req, res, next) => {
  try { await pool.query('SELECT 1'); res.json({ status: 'ok' }); }
  catch (error) { next(error); }
});

app.post('/api/auth/login', loginLimiter, async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = req.body?.password;
    if (!username || typeof password !== 'string' || password.length > 1024) {
      return res.status(400).json({ error: 'Username e password obbligatori' });
    }
    const result = await pool.query(
      'SELECT id, username, password_hash, role, active FROM app_users WHERE username=$1',
      [username]
    );
    const user = result.rows[0];
    if (!user || !user.active || !(await argon2.verify(user.password_hash, password))) {
      return res.status(401).json({ error: 'Credenziali non valide' });
    }
    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    req.session.userId = user.id;
    await pool.query('UPDATE app_users SET last_login_at=NOW() WHERE id=$1', [user.id]);
    res.json({ user: publicUser(user) });
  } catch (error) { next(error); }
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(error => {
    if (error) return res.status(500).json({ error: 'Impossibile chiudere la sessione' });
    res.clearCookie('assetclient.sid', { httpOnly: true, secure: production, sameSite: 'strict' });
    res.status(204).end();
  });
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (_req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT id, username, role, active, created_at, last_login_at FROM app_users ORDER BY username'
    );
    res.json({ users: result.rows });
  } catch (error) { next(error); }
});

app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const { username, password, role } = req.body || {};
    if (!validUsername(username)) return res.status(400).json({ error: 'Username: 3-64 caratteri alfanumerici, punto, trattino o underscore' });
    if (typeof password !== 'string' || password.length < 12 || password.length > 1024) {
      return res.status(400).json({ error: 'La password deve contenere almeno 12 caratteri' });
    }
    if (!['admin', 'operator'].includes(role)) return res.status(400).json({ error: 'Ruolo non valido' });
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const result = await pool.query(
      'INSERT INTO app_users(username,password_hash,role) VALUES($1,$2,$3) ON CONFLICT(username) DO NOTHING RETURNING id,username,role,active,created_at',
      [username, hash, role]
    );
    if (!result.rowCount) return res.status(409).json({ error: 'Username già esistente' });
    res.status(201).json({ user: result.rows[0] });
  } catch (error) { next(error); }
});

app.patch('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'ID non valido' });
    const { active, role, password } = req.body || {};
    if (active === undefined && role === undefined && password === undefined) {
      return res.status(400).json({ error: 'Nessuna modifica richiesta' });
    }
    if (role !== undefined && !['admin', 'operator'].includes(role)) return res.status(400).json({ error: 'Ruolo non valido' });
    if (password !== undefined && (typeof password !== 'string' || password.length < 12 || password.length > 1024)) {
      return res.status(400).json({ error: 'La password deve contenere almeno 12 caratteri' });
    }
    if (active !== undefined && typeof active !== 'boolean') return res.status(400).json({ error: 'active deve essere booleano' });
    if (id === Number(req.user.id) && (active === false || role === 'operator')) {
      return res.status(400).json({ error: 'Non puoi disattivare o declassare il tuo account' });
    }
    const current = await pool.query('SELECT id, role FROM app_users WHERE id=$1', [id]);
    if (!current.rowCount) return res.status(404).json({ error: 'Utente non trovato' });
    if (current.rows[0].role === 'admin' && (active === false || role === 'operator')) {
      const admins = await pool.query("SELECT COUNT(*)::int AS n FROM app_users WHERE role='admin' AND active=TRUE");
      if (admins.rows[0].n <= 1) return res.status(400).json({ error: 'Deve rimanere almeno un amministratore attivo' });
    }
    const updates = [], values = [];
    const set = (column, value) => { values.push(value); updates.push(column + '=$' + values.length); };
    if (active !== undefined) set('active', active);
    if (role !== undefined) set('role', role);
    if (password !== undefined) set('password_hash', await argon2.hash(password, { type: argon2.argon2id }));
    set('updated_at', new Date());
    values.push(id);
    const result = await pool.query(
      `UPDATE app_users SET ${updates.join(',')} WHERE id=$${values.length} RETURNING id,username,role,active,created_at,last_login_at`,
      values
    );
    res.json({ user: result.rows[0] });
  } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
  console.error('API error:', error.message);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Errore interno del server' });
});

initialize().then(() => {
  app.listen(port, '0.0.0.0', () => console.log(`Asset Client API in ascolto sulla porta ${port}`));
}).catch(error => {
  console.error('Avvio API fallito:', error);
  process.exit(1);
});

process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });
