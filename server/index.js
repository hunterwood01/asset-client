'use strict';

const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
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
app.use(express.json({ limit: '8mb', type: 'application/json' }));
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
    secure: production && String(process.env.APP_ORIGIN || '').startsWith('https://'),
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// Audit di tutte le richieste API che modificano dati; nessuna scadenza automatica dei record.
function auditSafe(value, key = '') {
  if (/password|token|secret|authorization|cookie/i.test(key)) return '[redatto]';
  if (Array.isArray(value)) return value.slice(0, 100).map(v => auditSafe(v));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 100).map(([k, v]) => [k, auditSafe(v, k)]));
  if (typeof value === 'string') return value.slice(0, 1000);
  return value;
}
app.use((req, res, next) => {
  if (!req.path.startsWith('/api/') || !['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) || ['/api/auth/login', '/api/auth/logout'].includes(req.path)) return next();
  res.on('finish', () => {
    const userId = req.session?.userId;
    if (!userId || res.statusCode < 200 || res.statusCode >= 400) return;
    let details = auditSafe(req.body || {});
    if (req.path === '/api/inventory-state' && req.method === 'PUT') {
      const state = req.body?.state || {};
      details = { revision: req.body?.revision ?? null, counts: { branches: state.branches?.length || 0, devices: state.devices?.length || 0, purchases: state.purchases?.length || 0 }, fields: Object.keys(state) };
    }
    pool.query('INSERT INTO audit_log(actor_user_id, action, method, endpoint, entity_id, details, status_code) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7)', [userId, req.method + ' ' + req.path, req.method, req.path, req.params?.id || null, JSON.stringify(details), res.statusCode]).catch(err => console.error('Audit insert failed:', err.message));
  });
  next();
});

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
      must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS app_users_active_idx ON app_users(active);
  `);

  await pool.query('ALTER TABLE app_users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE');

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id BIGSERIAL PRIMARY KEY,
      actor_user_id BIGINT REFERENCES app_users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      method TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      entity_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      status_code INTEGER NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS audit_log_created_at_idx ON audit_log(created_at DESC);
    CREATE INDEX IF NOT EXISTS audit_log_actor_idx ON audit_log(actor_user_id, created_at DESC);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS webex_sync_runs (
      id BIGSERIAL PRIMARY KEY,
      status TEXT NOT NULL CHECK (status IN ('running','success','error')),
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      finished_at TIMESTAMPTZ,
      records_read INTEGER NOT NULL DEFAULT 0,
      error_message TEXT,
      created_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS webex_sync_runs_started_idx ON webex_sync_runs(started_at DESC);
    CREATE TABLE IF NOT EXISTS webex_device_snapshots (
      webex_device_id TEXT PRIMARY KEY,
      serial_number TEXT,
      normalized_serial TEXT,
      product TEXT,
      model TEXT,
      mac TEXT,
      device_type TEXT,
      connection_status TEXT,
      person_id TEXT,
      person_email TEXT,
      person_name TEXT,
      workspace_id TEXT,
      workspace_name TEXT,
      location_id TEXT,
      location_name TEXT,
      suggested_branch_name TEXT,
      display_name TEXT,
      raw_safe JSONB NOT NULL DEFAULT '{}'::jsonb,
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_sync_run_id BIGINT REFERENCES webex_sync_runs(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS webex_device_serial_idx ON webex_device_snapshots(normalized_serial);
    CREATE TABLE IF NOT EXISTS webex_device_alerts (
      id BIGSERIAL PRIMARY KEY,
      alert_type TEXT NOT NULL CHECK (alert_type IN ('unknown_serial','serial_unavailable')),
      webex_device_id TEXT NOT NULL,
      normalized_serial TEXT NOT NULL DEFAULT '',
      serial_number TEXT,
      product TEXT,
      mac TEXT,
      display_name TEXT,
      person_email TEXT,
      person_name TEXT,
      workspace_id TEXT,
      workspace_name TEXT,
      location_name TEXT,
      suggested_branch_name TEXT,
      status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','acknowledged','resolved')),
      resolution_reason TEXT,
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      resolved_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(alert_type, webex_device_id, normalized_serial)
    );
    CREATE INDEX IF NOT EXISTS webex_device_alerts_status_idx ON webex_device_alerts(status, last_seen_at DESC);
  `);

  await pool.query(`
    ALTER TABLE webex_device_snapshots ADD COLUMN IF NOT EXISTS person_name TEXT;
    ALTER TABLE webex_device_snapshots ADD COLUMN IF NOT EXISTS location_name TEXT;
    ALTER TABLE webex_device_snapshots ADD COLUMN IF NOT EXISTS suggested_branch_name TEXT;
    ALTER TABLE webex_device_alerts ADD COLUMN IF NOT EXISTS person_name TEXT;
    ALTER TABLE webex_device_alerts ADD COLUMN IF NOT EXISTS location_name TEXT;
    ALTER TABLE webex_device_alerts ADD COLUMN IF NOT EXISTS suggested_branch_name TEXT;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cisco_product_lifecycle (
      product_id TEXT PRIMARY KEY,
      product_description TEXT,
      bulletin_number TEXT,
      bulletin_url TEXT,
      announcement_date TEXT,
      end_of_sale_date TEXT,
      end_of_sw_maintenance_date TEXT,
      end_of_security_support_date TEXT,
      last_date_of_support TEXT,
      end_of_service_contract_renewal TEXT,
      source_url TEXT NOT NULL,
      checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      response_status TEXT NOT NULL,
      raw_response JSONB NOT NULL DEFAULT '{}'::jsonb
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  for (const migrationVersion of ['001_shared_inventory', '002_finance_shared_state']) {
    const applied = await pool.query('SELECT 1 FROM schema_migrations WHERE version=$1', [migrationVersion]);
    if (!applied.rowCount) {
      const migrationPath = path.join(__dirname, 'migrations', migrationVersion + '.sql');
      const migrationSql = await fs.readFile(migrationPath, 'utf8');
      await pool.query(migrationSql);
      await pool.query('INSERT INTO schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING', [migrationVersion]);
    }
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS shared_inventory_state (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      state JSONB NOT NULL,
      revision BIGINT NOT NULL DEFAULT 1,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_by BIGINT REFERENCES app_users(id) ON DELETE SET NULL
    )
  `);

  const username = String(process.env.BOOTSTRAP_ADMIN_USERNAME || '').trim();
  const password = String(process.env.BOOTSTRAP_ADMIN_PASSWORD || '');
  if (username && password) {
    if (username.length < 3 || username.length > 64 || !validPassword(password)) {
      throw new Error('Bootstrap admin: password con almeno 12 caratteri, maiuscola, numero e carattere speciale');
    }
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    await pool.query(
      `INSERT INTO app_users(username,password_hash,role,must_change_password) VALUES($1,$2,'admin',TRUE)
       ON CONFLICT (username) DO NOTHING`,
      [username, hash]
    );
  }
}

function validPassword(value) {
  return typeof value === 'string' && value.length >= 12 && value.length <= 1024 && /[A-Z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}
function passwordPolicyMessage() {
  return 'La password deve avere almeno 12 caratteri, una maiuscola, un numero e un carattere speciale';
}
function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role, mustChangePassword: Boolean(user.must_change_password) };
}
async function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Autenticazione richiesta' });
  try {
    const result = await pool.query(
      'SELECT id, username, role, active, must_change_password FROM app_users WHERE id=$1',
      [req.session.userId]
    );
    const user = result.rows[0];
    if (!user || !user.active) {
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'Sessione non valida' });
    }
    req.user = user;
    if (user.must_change_password && !['/api/auth/me', '/api/auth/change-password', '/api/auth/logout'].includes(req.path)) {
      return res.status(403).json({ error: 'Devi cambiare la password prima di continuare', code: 'PASSWORD_CHANGE_REQUIRED' });
    }
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
      'SELECT id, username, password_hash, role, active, must_change_password FROM app_users WHERE username=$1',
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

app.post('/api/auth/change-password', requireAuth, async (req, res, next) => {
  try {
    const password = req.body?.password;
    const confirmation = req.body?.confirmation;
    if (!validPassword(password)) return res.status(400).json({ error: passwordPolicyMessage() });
    if (password !== confirmation) return res.status(400).json({ error: 'Le due password non coincidono' });
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const result = await pool.query('UPDATE app_users SET password_hash=$1, must_change_password=FALSE, updated_at=NOW() WHERE id=$2 AND active=TRUE RETURNING id,username,role,active,must_change_password', [hash, req.user.id]);
    if (!result.rowCount) return res.status(401).json({ error: 'Account non disponibile' });
    req.user = result.rows[0];
    res.json({ user: publicUser(req.user) });
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

app.get('/api/admin/audit', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 200));
    const before = req.query.before ? Number(req.query.before) : null;
    const result = await pool.query(`SELECT a.id, a.action, a.method, a.endpoint, a.entity_id, a.details, a.status_code, a.created_at, u.username AS actor_username FROM audit_log a LEFT JOIN app_users u ON u.id=a.actor_user_id WHERE ($1::bigint IS NULL OR a.id<$1) ORDER BY a.id DESC LIMIT $2`, [Number.isSafeInteger(before) && before > 0 ? before : null, limit]);
    res.json({ events: result.rows, retention: 'forever' });
  } catch (error) { next(error); }
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
    if (!validPassword(password)) return res.status(400).json({ error: passwordPolicyMessage() });
    if (!['admin', 'operator'].includes(role)) return res.status(400).json({ error: 'Ruolo non valido' });
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    const result = await pool.query(
      'INSERT INTO app_users(username,password_hash,role,must_change_password) VALUES($1,$2,$3,TRUE) ON CONFLICT(username) DO NOTHING RETURNING id,username,role,active,created_at,must_change_password',
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
    if (password !== undefined && !validPassword(password)) return res.status(400).json({ error: passwordPolicyMessage() });
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
    if (password !== undefined) {
      set('password_hash', await argon2.hash(password, { type: argon2.argon2id }));
      set('must_change_password', true);
    }
    set('updated_at', new Date());
    values.push(id);
    const result = await pool.query(
      `UPDATE app_users SET ${updates.join(',')} WHERE id=$${values.length} RETURNING id,username,role,active,created_at,last_login_at`,
      values
    );
    res.json({ user: result.rows[0] });
  } catch (error) { next(error); }
});


function requireOperator(req, res, next) {
  if (!['admin', 'operator'].includes(req.user?.role)) return res.status(403).json({ error: 'Permesso insufficiente' });
  next();
}
const asInt = value => Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : null;
const cleanString = (value, max = 500) => typeof value === 'string' ? value.trim().slice(0, max) : '';

app.get('/api/branches', requireAuth, requireOperator, async (_req, res, next) => {
  try {
    const r = await pool.query(`SELECT id, company_name AS "ragioneSociale", name, code, phone_prefix AS "phonePrefix", network_lan AS "networkLan", network_services AS "networkServices", network_guest AS "networkGuest", wlc, voice, old_name AS "oldName", new_name AS "newName", monthly_revenue AS "monthlyRevenue" FROM branches WHERE active=TRUE ORDER BY name`);
    res.json({ branches: r.rows });
  } catch (e) { next(e); }
});
app.post('/api/branches', requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const b=req.body||{}, name=cleanString(b.name,200), company=cleanString(b.ragioneSociale,200);
    if(!name) return res.status(400).json({error:'Nome filiale obbligatorio'});
    const r=await pool.query(`INSERT INTO branches(company_name,name,code,phone_prefix,network_lan,network_services,network_guest,wlc,voice,old_name,new_name,monthly_revenue)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT(company_name,name) DO UPDATE SET code=EXCLUDED.code,phone_prefix=EXCLUDED.phone_prefix,network_lan=EXCLUDED.network_lan,network_services=EXCLUDED.network_services,network_guest=EXCLUDED.network_guest,wlc=EXCLUDED.wlc,voice=EXCLUDED.voice,old_name=EXCLUDED.old_name,new_name=EXCLUDED.new_name,monthly_revenue=EXCLUDED.monthly_revenue,active=TRUE,updated_at=NOW()
      RETURNING id,company_name AS "ragioneSociale",name,code,monthly_revenue AS "monthlyRevenue"`,
      [company,name,cleanString(b.code,100)||null,cleanString(b.phonePrefix,100),cleanString(b.networkLan,200),cleanString(b.networkServices,200),cleanString(b.networkGuest,200),cleanString(b.wlc,200),cleanString(b.voice,200),cleanString(b.oldName,200),cleanString(b.newName,200),Math.max(0,Number(b.monthlyRevenue)||0)]);
    res.status(201).json({branch:r.rows[0]});
  } catch(e){next(e);}
});
app.get('/api/devices', requireAuth, requireOperator, async (_req,res,next)=>{
 try{
  const r=await pool.query(`SELECT d.id,d.serial,d.asset_tag AS "assetTag",d.type,d.brand,d.model,d.status,d.branch_id AS "branchId",d.warehouse_id AS "warehouseId",d.owner_type AS "ownerType",d.assigned_to AS "assignedTo",d.purchase_cost AS "purchaseCost",d.purchase_date AS "purchaseDate",d.activation_date AS "activationDate",d.monthly_fee AS "monthlyFee",d.useful_life_months AS "usefulLifeMonths",d.notes,d.lot_id AS "lotId",b.name AS "branchName",w.name AS "warehouseName" FROM devices d LEFT JOIN branches b ON b.id=d.branch_id LEFT JOIN warehouses w ON w.id=d.warehouse_id ORDER BY d.id DESC`);
  res.json({devices:r.rows});
 }catch(e){next(e);}
});
app.post('/api/devices', requireAuth, requireOperator, async(req,res,next)=>{
 try{
  const d=req.body||{},serial=cleanString(d.serial,200),type=cleanString(d.type,100);
  if(!serial||!type)return res.status(400).json({error:'Matricola e tipologia obbligatorie'});
  const branchId=d.branchId?asInt(d.branchId):null,warehouseId=d.warehouseId?asInt(d.warehouseId):null;
  if(d.branchId&&!branchId||d.warehouseId&&!warehouseId)return res.status(400).json({error:'Filiale o magazzino non valido'});
  if(branchId&&warehouseId)return res.status(400).json({error:'Un dispositivo non può essere in filiale e magazzino contemporaneamente'});
  const owner=['company','customer','unknown'].includes(d.ownerType)?d.ownerType:'unknown';
  const r=await pool.query(`INSERT INTO devices(serial,asset_tag,type,brand,model,status,branch_id,warehouse_id,owner_type,assigned_to,purchase_cost,purchase_date,activation_date,monthly_fee,useful_life_months,notes,lot_id)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
   ON CONFLICT(serial) DO UPDATE SET asset_tag=EXCLUDED.asset_tag,type=EXCLUDED.type,brand=EXCLUDED.brand,model=EXCLUDED.model,status=EXCLUDED.status,branch_id=EXCLUDED.branch_id,warehouse_id=EXCLUDED.warehouse_id,owner_type=EXCLUDED.owner_type,assigned_to=EXCLUDED.assigned_to,purchase_cost=EXCLUDED.purchase_cost,purchase_date=EXCLUDED.purchase_date,activation_date=EXCLUDED.activation_date,monthly_fee=EXCLUDED.monthly_fee,useful_life_months=EXCLUDED.useful_life_months,notes=EXCLUDED.notes,lot_id=EXCLUDED.lot_id,updated_at=NOW()
   RETURNING id,serial,type,status,branch_id AS "branchId",warehouse_id AS "warehouseId",owner_type AS "ownerType"`,
   [serial,cleanString(d.assetTag,200)||null,type,cleanString(d.brand,200),cleanString(d.model,200),cleanString(d.status,100)||'Disponibile',branchId,warehouseId,owner,cleanString(d.assignedTo,200),Math.max(0,Number(d.purchaseCost)||0),d.purchaseDate||null,d.activationDate||null,Math.max(0,Number(d.monthlyFee)||0),Math.max(1,Math.floor(Number(d.usefulLifeMonths)||36)),cleanString(d.notes,4000),cleanString(d.lotId,200)||null]);
  res.status(201).json({device:r.rows[0]});
 }catch(e){if(e.code==='23505')return res.status(409).json({error:'Matricola o asset tag già presente'});next(e);}
});
app.get('/api/warehouses',requireAuth,requireOperator,async(_req,res,next)=>{
 try{const r=await pool.query('SELECT id,code,name,location_description AS "locationDescription",default_owner AS "defaultOwner" FROM warehouses WHERE active=TRUE ORDER BY name');res.json({warehouses:r.rows});}catch(e){next(e);}
});
app.get('/api/license-purchases',requireAuth,requireOperator,async(_req,res,next)=>{
 try{const r=await pool.query(`SELECT id,category,supplier,package_name AS "packageName",quantity,unit_cost AS "unitCost",(unit_cost*quantity) AS "totalCost",currency,purchase_date AS "purchaseDate",start_date AS "startDate",expiry_date AS "expiryDate",reference,notes FROM license_purchases ORDER BY purchase_date DESC,id DESC`);res.json({purchases:r.rows});}catch(e){next(e);}
});
app.post('/api/license-purchases',requireAuth,requireOperator,async(req,res,next)=>{
 try{const p=req.body||{},quantity=Math.floor(Number(p.quantity)),unitCost=p.unitCost!==undefined?Number(p.unitCost):(Number(p.totalCost)||0)/Math.max(1,quantity);
 if(!['webex','router'].includes(p.category)||!cleanString(p.packageName,200)||!Number.isInteger(quantity)||quantity<1||!p.purchaseDate||!p.startDate||!p.expiryDate||p.expiryDate<p.startDate||!Number.isFinite(unitCost)||unitCost<0)return res.status(400).json({error:'Dati acquisto licenze non validi'});
 const r=await pool.query(`INSERT INTO license_purchases(category,supplier,package_name,quantity,unit_cost,currency,purchase_date,start_date,expiry_date,reference,notes,created_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id,category,package_name AS "packageName",quantity,unit_cost AS "unitCost",(unit_cost*quantity) AS "totalCost",purchase_date AS "purchaseDate",start_date AS "startDate",expiry_date AS "expiryDate"`,
 [p.category,cleanString(p.supplier,200),cleanString(p.packageName,200),quantity,unitCost,cleanString(p.currency,3)||'EUR',p.purchaseDate,p.startDate,p.expiryDate,cleanString(p.reference,200),cleanString(p.notes,2000),req.user.id]);
 res.status(201).json({purchase:r.rows[0]});
 }catch(e){next(e);}
});
app.get('/api/license-allocations',requireAuth,requireOperator,async(_req,res,next)=>{
 try{const r=await pool.query(`SELECT id,purchase_id AS "purchaseId",branch_id AS "branchId",quantity,assigned_at AS "assignedAt",released_at AS "releasedAt",notes FROM license_allocations ORDER BY id`);res.json({allocations:r.rows});}catch(e){next(e);}
});
app.post('/api/license-allocations',requireAuth,requireOperator,async(req,res,next)=>{
 const c=await pool.connect();
 try{const a=req.body||{},purchaseId=asInt(a.purchaseId),branchId=asInt(a.branchId),quantity=Math.floor(Number(a.quantity));
 if(!purchaseId||!branchId||!Number.isInteger(quantity)||quantity<1)return res.status(400).json({error:'Pacchetto, filiale e quantità sono obbligatori'});
 await c.query('BEGIN');
 const p=await c.query('SELECT quantity FROM license_purchases WHERE id=$1 FOR UPDATE',[purchaseId]);
 if(!p.rowCount){await c.query('ROLLBACK');return res.status(404).json({error:'Pacchetto licenze non trovato'});}
 const total=await c.query('SELECT COALESCE(SUM(quantity),0)::int AS n FROM license_allocations WHERE purchase_id=$1 AND released_at IS NULL',[purchaseId]);
 if(total.rows[0].n+quantity>p.rows[0].quantity){await c.query('ROLLBACK');return res.status(409).json({error:'Quantità da allocare superiore al residuo disponibile'});}
 const r=await c.query('INSERT INTO license_allocations(purchase_id,branch_id,quantity,assigned_at,notes) VALUES($1,$2,$3,$4,$5) RETURNING id,purchase_id AS "purchaseId",branch_id AS "branchId",quantity,assigned_at AS "assignedAt"',[purchaseId,branchId,quantity,a.assignedAt||new Date().toISOString().slice(0,10),cleanString(a.notes,1000)]);
 await c.query('COMMIT');res.status(201).json({allocation:r.rows[0]});
 }catch(e){await c.query('ROLLBACK').catch(()=>{});next(e);}finally{c.release();}
});
app.get('/api/stock-movements',requireAuth,requireOperator,async(_req,res,next)=>{
 try{const r=await pool.query(`SELECT id,device_id AS "deviceId",movement_type AS "movementType",from_warehouse_id AS "fromWarehouseId",to_warehouse_id AS "toWarehouseId",from_branch_id AS "fromBranchId",to_branch_id AS "toBranchId",owner_before AS "ownerBefore",owner_after AS "ownerAfter",occurred_at AS "occurredAt",reference,notes FROM stock_movements ORDER BY occurred_at DESC,id DESC LIMIT 1000`);res.json({movements:r.rows});}catch(e){next(e);}
});
app.post('/api/stock-movements',requireAuth,requireOperator,async(req,res,next)=>{
 const c=await pool.connect();
 try{const m=req.body||{},deviceId=asInt(m.deviceId);
 const types=['purchase','transfer','branch_assignment','return_to_stock','repair_out','repair_in','retirement','ownership_change'];
 if(!deviceId||!types.includes(m.movementType))return res.status(400).json({error:'Dispositivo o tipo movimento non valido'});
 await c.query('BEGIN');
 const current=await c.query('SELECT id,branch_id,warehouse_id,owner_type FROM devices WHERE id=$1 FOR UPDATE',[deviceId]);
 if(!current.rowCount){await c.query('ROLLBACK');return res.status(404).json({error:'Dispositivo non trovato'});}
 const d=current.rows[0],toBranch=m.toBranchId?asInt(m.toBranchId):null,toWarehouse=m.toWarehouseId?asInt(m.toWarehouseId):null;
 if(toBranch&&toWarehouse){await c.query('ROLLBACK');return res.status(400).json({error:'Destinazione ambigua'});}
 const ownerAfter=['company','customer','unknown'].includes(m.ownerAfter)?m.ownerAfter:d.owner_type;
 await c.query(`INSERT INTO stock_movements(device_id,movement_type,from_warehouse_id,to_warehouse_id,from_branch_id,to_branch_id,owner_before,owner_after,performed_by,reference,notes)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
 [deviceId,m.movementType,d.warehouse_id,toWarehouse,d.branch_id,toBranch,d.owner_type,ownerAfter,req.user.id,cleanString(m.reference,200),cleanString(m.notes,2000)]);
 await c.query('UPDATE devices SET branch_id=$1,warehouse_id=$2,owner_type=$3,updated_at=NOW() WHERE id=$4',[toBranch,toWarehouse,ownerAfter,deviceId]);
 await c.query('COMMIT');res.status(201).json({status:'ok'});
 }catch(e){await c.query('ROLLBACK').catch(()=>{});next(e);}finally{c.release();}
});


app.get('/api/inventory-state',requireAuth,requireOperator,async(_req,res,next)=>{try{const r=await pool.query('SELECT state,revision,updated_at AS "updatedAt" FROM shared_inventory_state WHERE id=1');res.json(r.rowCount?r.rows[0]:{state:null,revision:0,updatedAt:null});}catch(e){next(e);}});
app.put('/api/inventory-state',requireAuth,requireOperator,async(req,res,next)=>{try{
 const state=req.body?.state,revision=Number(req.body?.revision);
 if(!state||typeof state!=='object'||Array.isArray(state))return res.status(400).json({error:'Snapshot inventario non valido'});
 if(!Number.isSafeInteger(revision)||revision<0)return res.status(400).json({error:'Revisione non valida'});
 const encoded=JSON.stringify(state);if(Buffer.byteLength(encoded,'utf8')>8*1024*1024)return res.status(413).json({error:'Snapshot troppo grande (limite 8 MB)'});
 const c=await pool.connect();try{await c.query('BEGIN');await c.query('SELECT pg_advisory_xact_lock(748213)');const cur=await c.query('SELECT revision FROM shared_inventory_state WHERE id=1 FOR UPDATE');const actual=cur.rowCount?Number(cur.rows[0].revision):0;
 if(actual!==revision){await c.query('ROLLBACK');return res.status(409).json({error:'I dati sono cambiati in un’altra sessione. Ricarica la pagina prima di continuare.',revision:actual});}
 const next=actual+1;await c.query('INSERT INTO shared_inventory_state(id,state,revision,updated_at,updated_by) VALUES(1,$1::jsonb,$2,NOW(),$3) ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state,revision=EXCLUDED.revision,updated_at=NOW(),updated_by=EXCLUDED.updated_by',[encoded,next,req.user.id]);await c.query('COMMIT');res.json({revision:next,updatedAt:new Date().toISOString()});
 }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}
}catch(e){next(e);}});


// Read-only operational health checks. Missing deployment metrics are reported as unavailable.
let ciscoEoxToken = '';
let ciscoEoxTokenExpiresAt = 0;
async function getCiscoEoxToken() {
  if (ciscoEoxToken && Date.now() < ciscoEoxTokenExpiresAt - 60000) return ciscoEoxToken;
  const id = process.env.CISCO_EOX_CLIENT_ID, secret = process.env.CISCO_EOX_CLIENT_SECRET;
  if (!id || !secret) throw Object.assign(new Error('Cisco Support API non configurata: mancano le credenziali EoX.'), { statusCode: 409 });
  const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: id, client_secret: secret });
  const response = await fetch('https://id.cisco.com/oauth2/default/v1/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body, signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw new Error('Autenticazione Cisco Support API fallita (HTTP ' + response.status + ')');
  const data = await response.json();
  if (!data.access_token) throw new Error('Cisco Support API non ha restituito un access token');
  ciscoEoxToken = data.access_token;
  ciscoEoxTokenExpiresAt = Date.now() + Math.max(60, Number(data.expires_in) || 3600) * 1000;
  return ciscoEoxToken;
}
app.get('/api/admin/lifecycle', requireAuth, requireAdmin, async (_req,res,next) => {
  try {
    const r = await pool.query('SELECT product_id AS "productId",product_description AS "productDescription",bulletin_number AS "bulletinNumber",bulletin_url AS "bulletinUrl",announcement_date AS "announcementDate",end_of_sale_date AS "endOfSaleDate",end_of_sw_maintenance_date AS "endOfSwMaintenanceDate",end_of_security_support_date AS "endOfSecuritySupportDate",last_date_of_support AS "lastDateOfSupport",end_of_service_contract_renewal AS "endOfServiceContractRenewal",source_url AS "sourceUrl",checked_at AS "checkedAt",response_status AS "responseStatus" FROM cisco_product_lifecycle ORDER BY product_id LIMIT 500');
    res.json({ configured: Boolean(process.env.CISCO_EOX_CLIENT_ID && process.env.CISCO_EOX_CLIENT_SECRET), products: r.rows });
  } catch(e) { next(e); }
});
app.post('/api/admin/lifecycle/lookup', requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const productId = cleanString(req.body?.productId, 250);
    if (!productId || /[,/?#]/.test(productId)) return res.status(400).json({ error: 'Inserisci un PID Cisco esatto, senza wildcard o liste multiple.' });
    const token = await getCiscoEoxToken();
    const sourceUrl = 'https://apix.cisco.com/supporttools/eox/rest/5/EOXByProductID/1/' + encodeURIComponent(productId) + '?responseencoding=json';
    const response = await fetch(sourceUrl, { headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' }, signal: AbortSignal.timeout(20000) });
    if (!response.ok) throw new Error('Cisco EoX API ha restituito HTTP ' + response.status);
    const body = await response.json();
    const raw = Array.isArray(body.EOXRecord) ? body.EOXRecord[0] : body.EOXRecord;
    if (!raw) return res.status(404).json({ error: body.EOXError?.ErrorDescription || 'Nessun record EoX restituito per il PID esatto.' });
    const dateValue = v => typeof v === 'string' ? v.trim() : (v && typeof v.value === 'string' ? v.value.trim() : '');
    const values = {
      productId: cleanString(raw.EOLProductID || productId, 250),
      description: cleanString(raw.ProductIDDescription, 500),
      bulletin: cleanString(raw.ProductBulletinNumber, 100),
      bulletinUrl: cleanString(raw.LinkToProductBulletinURL, 1000),
      announcement: dateValue(raw.EOXExternalAnnouncementDate),
      endSale: dateValue(raw.EndOfSaleDate),
      endSw: dateValue(raw.EndOfSWMaintenanceReleases),
      endSecurity: dateValue(raw.EndOfSecurityVulSupportDate),
      lastSupport: dateValue(raw.LastDateOfSupport),
      contractRenewal: dateValue(raw.EndOfServiceContractRenewal)
    };
    await pool.query(`INSERT INTO cisco_product_lifecycle(product_id,product_description,bulletin_number,bulletin_url,announcement_date,end_of_sale_date,end_of_sw_maintenance_date,end_of_security_support_date,last_date_of_support,end_of_service_contract_renewal,source_url,checked_at,response_status,raw_response)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),'success',$12::jsonb)
      ON CONFLICT(product_id) DO UPDATE SET product_description=EXCLUDED.product_description,bulletin_number=EXCLUDED.bulletin_number,bulletin_url=EXCLUDED.bulletin_url,announcement_date=EXCLUDED.announcement_date,end_of_sale_date=EXCLUDED.end_of_sale_date,end_of_sw_maintenance_date=EXCLUDED.end_of_sw_maintenance_date,end_of_security_support_date=EXCLUDED.end_of_security_support_date,last_date_of_support=EXCLUDED.last_date_of_support,end_of_service_contract_renewal=EXCLUDED.end_of_service_contract_renewal,source_url=EXCLUDED.source_url,checked_at=NOW(),response_status='success',raw_response=EXCLUDED.raw_response`,
      [values.productId,values.description,values.bulletin,values.bulletinUrl,values.announcement,values.endSale,values.endSw,values.endSecurity,values.lastSupport,values.contractRenewal,sourceUrl,JSON.stringify(raw)]);
    res.json({ product: { productId: values.productId, productDescription: values.description, bulletinNumber: values.bulletin, bulletinUrl: values.bulletinUrl, announcementDate: values.announcement, endOfSaleDate: values.endSale, endOfSwMaintenanceDate: values.endSw, endOfSecuritySupportDate: values.endSecurity, lastDateOfSupport: values.lastSupport, endOfServiceContractRenewal: values.contractRenewal, sourceUrl, checkedAt: new Date().toISOString(), responseStatus: 'success' } });
  } catch(e) { if(e.statusCode) return res.status(e.statusCode).json({ error: e.message }); next(e); }
});

app.get('/api/admin/system-status', requireAuth, requireAdmin, async (_req, res) => {
  const checkedAt = new Date().toISOString();
  const checks = [];
  checks.push({ id: 'api', label: 'Applicazione e API', status: 'ok', message: 'Endpoint API raggiungibile', checkedAt, details: { uptimeSeconds: Math.floor(process.uptime()), nodeVersion: process.version } });
  try {
    const started = Date.now();
    await pool.query('SELECT 1');
    checks.push({ id: 'database', label: 'Database', status: 'ok', message: 'Connessione e query di verifica riuscite', checkedAt, details: { latencyMs: Date.now() - started } });
  } catch {
    checks.push({ id: 'database', label: 'Database', status: 'error', message: 'Connessione o query di verifica non riuscita', checkedAt, details: {} });
  }
  try {
    const stat = await fs.statfs(process.cwd());
    const totalBytes = Number(stat.blocks) * Number(stat.bsize);
    const availableBytes = Number(stat.bavail) * Number(stat.bsize);
    const usedPercent = totalBytes > 0 ? Math.round(((totalBytes - availableBytes) / totalBytes) * 1000) / 10 : null;
    const status = usedPercent === null ? 'unknown' : usedPercent >= 95 ? 'error' : usedPercent >= 85 ? 'warning' : 'ok';
    checks.push({ id: 'disk', label: 'Spazio disco', status, message: usedPercent === null ? 'Metriche disco non disponibili' : usedPercent >= 95 ? 'Spazio disco critico' : usedPercent >= 85 ? 'Spazio disco in esaurimento' : 'Spazio disco nella soglia prevista', checkedAt, details: { totalBytes, availableBytes, usedPercent, path: process.cwd() } });
  } catch {
    checks.push({ id: 'disk', label: 'Spazio disco', status: 'unknown', message: 'Metriche disco non disponibili in questo ambiente', checkedAt, details: {} });
  }
  const configured = Boolean(process.env.WEBEX_ACCESS_TOKEN);
  let webex = { id: 'webex', label: 'Connettore Webex', status: 'unknown', message: configured ? 'Token configurato; sincronizzazione da verificare' : 'Non configurato: manca WEBEX_ACCESS_TOKEN', checkedAt, details: { configured } };
  try {
    const r = await pool.query('SELECT status, started_at, finished_at, records_read, error_message FROM webex_sync_runs ORDER BY id DESC LIMIT 1');
    if (r.rowCount) {
      const last = r.rows[0];
      webex = { ...webex, status: last.status === 'success' ? 'ok' : last.status === 'error' ? 'error' : 'warning', message: last.status === 'success' ? 'Ultima sincronizzazione completata' : last.error_message || 'Ultima sincronizzazione non completata', details: { ...webex.details, lastStatus: last.status, startedAt: last.started_at, finishedAt: last.finished_at, recordsRead: last.records_read } };
    }
  } catch {
    webex = { ...webex, status: 'unknown', message: 'Stato sincronizzazione non disponibile', details: { configured } };
  }
  try {
    const r = await pool.query('SELECT status, started_at, finished_at, records_read, error_message FROM webex_sync_runs ORDER BY id DESC LIMIT 10');
    checks.push({ id: 'jobs', label: 'Sincronizzazioni e processi', status: r.rows.some(x => x.status === 'error') ? 'warning' : 'ok', message: r.rowCount ? 'Storico delle sincronizzazioni disponibile' : 'Nessuna sincronizzazione eseguita', checkedAt, details: { recentRuns: r.rows } });
  } catch {
    checks.push({ id: 'jobs', label: 'Sincronizzazioni e processi', status: 'unknown', message: 'Storico processi non disponibile', checkedAt, details: {} });
  }
  checks.push(webex);
  const eoxConfigured = Boolean(process.env.CISCO_EOX_CLIENT_ID && process.env.CISCO_EOX_CLIENT_SECRET);
  checks.push({ id: 'cisco-eox', label: 'Cisco EoX', status: eoxConfigured ? 'unknown' : 'unknown', message: eoxConfigured ? 'Credenziali configurate; ultima verifica da eseguire con una ricerca PID' : 'Non configurato: mancano le credenziali Cisco Support API', checkedAt, details: { configured: eoxConfigured } });
  const order = { error: 0, warning: 1, unknown: 2, ok: 3 };
  res.json({ checkedAt, overall: checks.some(x => x.status === 'error') ? 'error' : checks.some(x => x.status === 'warning') ? 'warning' : checks.some(x => x.status === 'unknown') ? 'unknown' : 'ok', checks: checks.sort((a,b) => (order[a.status] ?? 2) - (order[b.status] ?? 2)) });
});

function normalizeSerial(value) {
  return String(value || '').trim().replace(/\s+/g, '').toUpperCase();
}
function webexSafeDevice(d) {
  return {
    id: String(d.id || ''),
    serialNumber: typeof d.serial === 'string' ? d.serial.trim() : '',
    product: cleanString(d.product, 200),
    model: cleanString(d.model, 200),
    mac: cleanString(d.mac, 100),
    deviceType: cleanString(d.type, 100),
    connectionStatus: cleanString(d.connectionStatus, 100),
    personId: cleanString(d.personId, 200),
    personEmail: cleanString(d.personEmail, 320),
    personName: cleanString(d.personName, 200),
    workspaceId: cleanString(d.workspaceId, 200),
    workspaceName: cleanString(d.workspaceName, 200),
    locationId: cleanString(d.locationId, 200),
    locationName: cleanString(d.locationName, 200),
    suggestedBranchName: cleanString(d.suggestedBranchName, 200),
    displayName: cleanString(d.displayName || d.name, 200)
  };
}
app.get('/api/admin/webex/status', requireAuth, requireAdmin, async (_req,res,next) => {
  try {
    const [run, counts, alerts] = await Promise.all([
      pool.query('SELECT id,status,started_at,finished_at,records_read,error_message FROM webex_sync_runs ORDER BY id DESC LIMIT 1'),
      pool.query('SELECT COUNT(*)::int AS devices FROM webex_device_snapshots'),
      pool.query("SELECT status,COUNT(*)::int AS count FROM webex_device_alerts GROUP BY status")
    ]);
    res.json({ configured: Boolean(process.env.WEBEX_ACCESS_TOKEN), lastRun: run.rows[0] || null, deviceCount: counts.rows[0].devices, alerts: alerts.rows, message: process.env.WEBEX_ACCESS_TOKEN ? null : 'Configura WEBEX_ACCESS_TOKEN nel secret store dell’ambiente server per abilitare la sincronizzazione.' });
  } catch(e) { next(e); }
});
app.post('/api/admin/webex/sync', requireAuth, requireAdmin, async (req,res,next) => {
  if (!process.env.WEBEX_ACCESS_TOKEN) return res.status(409).json({ error: 'Connettore non configurato: imposta WEBEX_ACCESS_TOKEN lato server.' });
  const run = await pool.query("INSERT INTO webex_sync_runs(status,created_by) VALUES('running',$1) RETURNING id", [req.user.id]);
  const runId = run.rows[0].id;
  try {
    let nextUrl = 'https://webexapis.com/v1/devices?max=100';
    const devices = [];
    let pages = 0;
    while (nextUrl) {
      if (++pages > 1000) throw new Error('Limite di paginazione superato');
      if (new URL(nextUrl).hostname !== 'webexapis.com') throw new Error('URL di paginazione Webex non autorizzato');
      const response = await fetch(nextUrl, { headers: { Authorization: 'Bearer ' + process.env.WEBEX_ACCESS_TOKEN, Accept: 'application/json' }, signal: AbortSignal.timeout(20000) });
      if (!response.ok) {
        const status = response.status;
        throw new Error(status === 401 || status === 403 ? 'Autorizzazione Webex non valida o permessi di lettura insufficienti (HTTP ' + status + ')' : 'API Webex ha restituito HTTP ' + status);
      }
      const body = await response.json();
      if (!Array.isArray(body.items)) throw new Error('Risposta API Webex inattesa: elenco dispositivi assente');
      devices.push(...body.items.map(webexSafeDevice).filter(d => d.id));
      const link = response.headers.get('link') || '';
      const match = link.match(/<([^>]+)>;\\s*rel="?next"?/i);
      nextUrl = match ? match[1] : '';
      if (devices.length > 100000) throw new Error('Limite di dispositivi superato');
    }
    // Directory enrichment is best-effort: a missing optional read scope must not invalidate the complete device inventory.
    async function readDirectory(url) {
      const items = [];
      let target = url, count = 0;
      try {
        while (target) {
          if (++count > 100) throw new Error('Directory pagination limit');
          if (new URL(target).hostname !== 'webexapis.com') return [];
          const response = await fetch(target, { headers: { Authorization: 'Bearer ' + process.env.WEBEX_ACCESS_TOKEN, Accept: 'application/json' }, signal: AbortSignal.timeout(12000) });
          if (!response.ok) return [];
          const body = await response.json();
          if (!Array.isArray(body.items)) return [];
          items.push(...body.items);
          const link = response.headers.get('link') || '';
          const match = link.match(/<([^>]+)>;\\s*rel="?next"?/i);
          target = match ? match[1] : '';
        }
      } catch { return []; }
      return items;
    }
    const [workspaces, people, locations] = await Promise.all([
      readDirectory('https://webexapis.com/v1/workspaces?max=100'),
      readDirectory('https://webexapis.com/v1/people?max=100'),
      readDirectory('https://webexapis.com/v1/locations?max=100')
    ]);
    const workspaceById = new Map(workspaces.map(x => [String(x.id), x]));
    const personById = new Map(people.map(x => [String(x.id), x]));
    const locationById = new Map(locations.map(x => [String(x.id), x]));
    const normLabel = value => String(value || '').trim().normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLocaleLowerCase('it').replace(/[^a-z0-9]/g,'');
    const inventoryBeforeBranchMatch = await pool.query('SELECT state FROM shared_inventory_state WHERE id=1');
    const knownBranches = inventoryBeforeBranchMatch.rows[0]?.state?.branches || [];
    for (const d of devices) {
      const ws = workspaceById.get(String(d.workspaceId || ''));
      const person = personById.get(String(d.personId || ''));
      if (ws) {
        d.workspaceName = d.workspaceName || cleanString(ws.name, 200);
        d.locationId = d.locationId || cleanString(ws.locationId, 200);
      }
      if (person) {
        d.personName = d.personName || cleanString(person.displayName || person.name, 200);
        d.personEmail = d.personEmail || cleanString(Array.isArray(person.emails) ? person.emails[0] : person.email, 320);
      }
      const loc = locationById.get(String(d.locationId || ''));
      if (loc) d.locationName = cleanString(loc.name, 200);
      const candidates = [d.locationName, d.workspaceName, d.displayName].map(normLabel).filter(Boolean);
      const matches = knownBranches.filter(b => [b.name,b.city,b.code,b.newName].map(normLabel).some(v => v && candidates.includes(v)));
      d.suggestedBranchName = matches.length === 1 ? String(matches[0].name || matches[0].city || matches[0].code || '') : '';
    }
    const inventory = await pool.query('SELECT state FROM shared_inventory_state WHERE id=1');
    const assetDevices = inventory.rows[0]?.state?.devices || [];
    const knownSerials = new Set(assetDevices.map(d => normalizeSerial(d.serial)).filter(Boolean));
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const d of devices) {
        const serial = d.serialNumber;
        const normalized = normalizeSerial(serial);
        await client.query(`INSERT INTO webex_device_snapshots(webex_device_id,serial_number,normalized_serial,product,model,mac,device_type,connection_status,person_id,person_email,person_name,workspace_id,workspace_name,location_id,location_name,suggested_branch_name,display_name,raw_safe,last_seen_at,last_sync_run_id)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18::jsonb,NOW(),$19)
          ON CONFLICT(webex_device_id) DO UPDATE SET serial_number=EXCLUDED.serial_number,normalized_serial=EXCLUDED.normalized_serial,product=EXCLUDED.product,model=EXCLUDED.model,mac=EXCLUDED.mac,device_type=EXCLUDED.device_type,connection_status=EXCLUDED.connection_status,person_id=EXCLUDED.person_id,person_email=EXCLUDED.person_email,person_name=EXCLUDED.person_name,workspace_id=EXCLUDED.workspace_id,workspace_name=EXCLUDED.workspace_name,location_id=EXCLUDED.location_id,location_name=EXCLUDED.location_name,suggested_branch_name=EXCLUDED.suggested_branch_name,display_name=EXCLUDED.display_name,raw_safe=EXCLUDED.raw_safe,last_seen_at=NOW(),last_sync_run_id=EXCLUDED.last_sync_run_id`,
          [d.id,serial||null,normalized||null,d.product,d.model,d.mac,d.deviceType,d.connectionStatus,d.personId,d.personEmail,d.personName,d.workspaceId,d.workspaceName,d.locationId,d.locationName,d.suggestedBranchName,d.displayName,JSON.stringify(d),runId]);
        const alertType = !normalized ? 'serial_unavailable' : !knownSerials.has(normalized) ? 'unknown_serial' : null;
        if (alertType) {
          await client.query(`INSERT INTO webex_device_alerts(alert_type,webex_device_id,normalized_serial,serial_number,product,mac,display_name,person_email,person_name,workspace_id,workspace_name,location_name,suggested_branch_name,status)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'new')
            ON CONFLICT(alert_type,webex_device_id,normalized_serial) DO UPDATE SET serial_number=EXCLUDED.serial_number,product=EXCLUDED.product,mac=EXCLUDED.mac,display_name=EXCLUDED.display_name,person_email=EXCLUDED.person_email,person_name=EXCLUDED.person_name,workspace_id=EXCLUDED.workspace_id,workspace_name=EXCLUDED.workspace_name,location_name=EXCLUDED.location_name,suggested_branch_name=EXCLUDED.suggested_branch_name,last_seen_at=NOW(),updated_at=NOW()`,
            [alertType,d.id,normalized,serial||null,d.product,d.mac,d.displayName,d.personEmail,d.personName,d.workspaceId,d.workspaceName,d.locationName,d.suggestedBranchName]);
          if (normalized) await client.query("UPDATE webex_device_alerts SET status='resolved',resolution_reason='serial now available from Webex',resolved_at=NOW(),updated_at=NOW() WHERE alert_type='serial_unavailable' AND webex_device_id=$1 AND status<>'resolved'",[d.id]);
        } else {
          await client.query("UPDATE webex_device_alerts SET status='resolved',resolution_reason='serial matched in Asset Client',resolved_at=NOW(),updated_at=NOW() WHERE alert_type='unknown_serial' AND webex_device_id=$1 AND status<>'resolved'",[d.id]);
          await client.query("UPDATE webex_device_alerts SET status='resolved',resolution_reason='serial now available from Webex',resolved_at=NOW(),updated_at=NOW() WHERE alert_type='serial_unavailable' AND webex_device_id=$1 AND status<>'resolved'",[d.id]);
        }
      }
      await client.query("UPDATE webex_sync_runs SET status='success',finished_at=NOW(),records_read=$1 WHERE id=$2",[devices.length,runId]);
      await client.query('COMMIT');
    } catch(e) { await client.query('ROLLBACK').catch(()=>{}); throw e; } finally { client.release(); }
    res.json({ status: 'success', runId, recordsRead: devices.length });
  } catch(e) {
    await pool.query("UPDATE webex_sync_runs SET status='error',finished_at=NOW(),error_message=$1 WHERE id=$2",[String(e.message || 'Errore sincronizzazione').slice(0,500),runId]).catch(()=>{});
    next(e);
  }
});
app.get('/api/admin/webex/alerts', requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const status = ['new','acknowledged','resolved'].includes(req.query.status) ? req.query.status : null;
    const r = await pool.query(`SELECT id,alert_type AS "alertType",webex_device_id AS "webexDeviceId",serial_number AS "serialNumber",product,mac,display_name AS "displayName",person_email AS "personEmail",person_name AS "personName",workspace_id AS "workspaceId",workspace_name AS "workspaceName",location_name AS "locationName",suggested_branch_name AS "suggestedBranchName",status,resolution_reason AS "resolutionReason",first_seen_at AS "firstSeenAt",last_seen_at AS "lastSeenAt",updated_at AS "updatedAt" FROM webex_device_alerts WHERE ($1::text IS NULL OR status=$1) ORDER BY CASE status WHEN 'new' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,last_seen_at DESC LIMIT 1000`,[status]);
    res.json({ alerts: r.rows });
  } catch(e) { next(e); }
});
app.patch('/api/admin/webex/alerts/:id', requireAuth, requireAdmin, async (req,res,next) => {
  try {
    const status = req.body?.status;
    if (!['acknowledged','resolved','new'].includes(status)) return res.status(400).json({ error: 'Stato avviso non valido' });
    const r = await pool.query("UPDATE webex_device_alerts SET status=$1,resolution_reason=$2,resolved_at=CASE WHEN $1='resolved' THEN NOW() ELSE NULL END,updated_at=NOW() WHERE id=$3 RETURNING id,status,resolution_reason AS \"resolutionReason\",updated_at AS \"updatedAt\"",[status,cleanString(req.body?.resolutionReason,500),Number(req.params.id)]);
    if (!r.rowCount) return res.status(404).json({ error: 'Avviso non trovato' });
    res.json({ alert: r.rows[0] });
  } catch(e) { next(e); }
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
