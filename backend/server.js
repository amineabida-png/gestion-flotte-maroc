const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'GFM_SECRET_2026_@#$';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../frontend/public')));

// ─── DATABASE SETUP ──────────────────────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'gfm.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'client',
    company TEXT DEFAULT '',
    phone TEXT DEFAULT '',
    plan TEXT DEFAULT 'month',
    expires_at TEXT,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  );

  CREATE TABLE IF NOT EXISTS vehicles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    plate TEXT NOT NULL,
    model TEXT NOT NULL,
    type TEXT DEFAULT 'Camion Semi',
    km INTEGER DEFAULT 0,
    fuel INTEGER DEFAULT 100,
    status TEXT DEFAULT 'disponible',
    insurance TEXT,
    maintenance TEXT,
    vignette TEXT,
    year INTEGER,
    color TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS drivers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    cin TEXT,
    phone TEXT,
    license TEXT DEFAULT 'C+E',
    city TEXT,
    salary REAL DEFAULT 0,
    status TEXT DEFAULT 'actif',
    missions INTEGER DEFAULT 0,
    rating REAL DEFAULT 5,
    dob TEXT,
    hire TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    client TEXT NOT NULL,
    origin TEXT NOT NULL,
    destination TEXT NOT NULL,
    driver_id INTEGER,
    vehicle_id INTEGER,
    status TEXT DEFAULT 'planifie',
    date TEXT,
    distance REAL DEFAULT 0,
    amount REAL DEFAULT 0,
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS invoices (
    id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL,
    client TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'en_attente',
    date TEXT,
    due TEXT,
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS fuels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    vehicle_id INTEGER,
    date TEXT,
    litres REAL DEFAULT 0,
    price_per_l REAL DEFAULT 14.50,
    station TEXT,
    km INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    vehicle_id INTEGER,
    type TEXT,
    amount REAL DEFAULT 0,
    date TEXT,
    description TEXT,
    justif INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS maintenances (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    vehicle_id INTEGER,
    type TEXT,
    date TEXT,
    km INTEGER DEFAULT 0,
    cost REAL DEFAULT 0,
    status TEXT DEFAULT 'planifie',
    notes TEXT,
    technicien TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    driver_id INTEGER,
    from_date TEXT,
    to_date TEXT,
    type TEXT DEFAULT 'Conge annuel',
    status TEXT DEFAULT 'en_attente',
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    type TEXT DEFAULT 'info',
    title TEXT NOT NULL,
    desc TEXT,
    read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id)
  );
`);

// ─── CREATE SUPER ADMIN IF NOT EXISTS ────────────────────────────────────────
const superExists = db.prepare("SELECT id FROM accounts WHERE role='super'").get();
if (!superExists) {
  const hash = bcrypt.hashSync('GFM2026@Admin', 10);
  db.prepare(`INSERT INTO accounts (name, email, password, role, company, plan, expires_at)
    VALUES (?, ?, ?, 'super', 'Gestion Flotte Maroc', 'life', '2099-12-31')`
  ).run('Super Admin', 'admin@gfm.ma', hash);
  console.log('✅ Super Admin created: admin@gfm.ma / GFM2026@Admin');
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const account = db.prepare('SELECT * FROM accounts WHERE id=?').get(decoded.id);
    if (!account) return res.status(401).json({ error: 'Compte introuvable' });
    if (account.status !== 'active') return res.status(403).json({ error: 'Compte suspendu' });
    if (account.role !== 'super' && account.plan !== 'life') {
      if (account.expires_at && new Date(account.expires_at) < new Date()) {
        return res.status(403).json({ error: 'Licence expirée', expired: true });
      }
    }
    req.account = account;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token invalide' });
  }
}

function superOnly(req, res, next) {
  if (req.account.role !== 'super') return res.status(403).json({ error: 'Accès refusé' });
  next();
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  const account = db.prepare('SELECT * FROM accounts WHERE email=?').get(email.toLowerCase().trim());
  if (!account) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  if (account.status !== 'active') return res.status(403).json({ error: 'Compte suspendu' });
  if (!bcrypt.compareSync(password, account.password)) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

  // Check expiry for non-super
  if (account.role !== 'super' && account.plan !== 'life') {
    if (account.expires_at && new Date(account.expires_at) < new Date()) {
      return res.status(403).json({ error: 'Votre licence a expiré. Contactez l administrateur.', expired: true });
    }
  }

  db.prepare("UPDATE accounts SET last_login=datetime('now') WHERE id=?").run(account.id);
  const token = jwt.sign({ id: account.id, role: account.role }, JWT_SECRET, { expiresIn: '30d' });
  const { password: _, ...accountData } = account;
  res.json({ token, account: accountData });
});

app.get('/api/me', auth, (req, res) => {
  const { password: _, ...accountData } = req.account;
  res.json(accountData);
});

app.post('/api/change-password', auth, (req, res) => {
  const { current, newPass } = req.body;
  if (!bcrypt.compareSync(current, req.account.password)) return res.status(400).json({ error: 'Mot de passe actuel incorrect' });
  const hash = bcrypt.hashSync(newPass, 10);
  db.prepare('UPDATE accounts SET password=? WHERE id=?').run(hash, req.account.id);
  res.json({ success: true });
});

// ─── SUPER ADMIN ROUTES ───────────────────────────────────────────────────────
app.get('/api/admin/accounts', auth, superOnly, (req, res) => {
  const accounts = db.prepare("SELECT id,name,email,role,company,phone,plan,expires_at,status,created_at,last_login FROM accounts ORDER BY created_at DESC").all();
  res.json(accounts);
});

app.post('/api/admin/accounts', auth, superOnly, (req, res) => {
  const { name, email, password, company, phone, plan, duration } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Nom, email et mot de passe requis' });
  const existing = db.prepare('SELECT id FROM accounts WHERE email=?').get(email.toLowerCase());
  if (existing) return res.status(400).json({ error: 'Email déjà utilisé' });
  const hash = bcrypt.hashSync(password, 10);
  let expires_at = null;
  if (plan === 'life') {
    expires_at = '2099-12-31';
  } else {
    const days = plan === 'month' ? 30 : plan === 'year' ? 365 : (parseInt(duration) || 30);
    const d = new Date();
    d.setDate(d.getDate() + days);
    expires_at = d.toISOString().split('T')[0];
  }
  const result = db.prepare(`INSERT INTO accounts (name,email,password,role,company,phone,plan,expires_at) VALUES (?,?,?,'client',?,?,?,?)`
  ).run(name, email.toLowerCase(), hash, company || '', phone || '', plan || 'month', expires_at);

  // Create default alerts for new account
  const newId = result.lastInsertRowid;
  db.prepare("INSERT INTO alerts (account_id,type,title,desc) VALUES (?,?,?,?)").run(newId, 'info', 'Bienvenue sur Gestion Flotte Maroc', 'Votre compte est actif. Commencez par ajouter vos vehicules.');

  res.json({ success: true, id: newId });
});

app.put('/api/admin/accounts/:id', auth, superOnly, (req, res) => {
  const { name, email, company, phone, plan, status, newPassword } = req.body;
  const id = req.params.id;
  const account = db.prepare('SELECT * FROM accounts WHERE id=?').get(id);
  if (!account) return res.status(404).json({ error: 'Compte introuvable' });
  let expires_at = account.expires_at;
  if (plan && plan !== account.plan) {
    if (plan === 'life') expires_at = '2099-12-31';
    else {
      const days = plan === 'month' ? 30 : plan === 'year' ? 365 : 30;
      const d = new Date();
      d.setDate(d.getDate() + days);
      expires_at = d.toISOString().split('T')[0];
    }
  }
  let password = account.password;
  if (newPassword) password = bcrypt.hashSync(newPassword, 10);
  db.prepare(`UPDATE accounts SET name=?,email=?,company=?,phone=?,plan=?,expires_at=?,status=?,password=? WHERE id=?`
  ).run(name || account.name, email || account.email, company || account.company, phone || account.phone, plan || account.plan, expires_at, status || account.status, password, id);
  res.json({ success: true });
});

app.delete('/api/admin/accounts/:id', auth, superOnly, (req, res) => {
  const id = req.params.id;
  if (req.account.id == id) return res.status(400).json({ error: 'Impossible de supprimer votre propre compte' });
  // Delete all data for this account
  ['vehicles','drivers','missions','invoices','fuels','expenses','maintenances','leaves','alerts']
    .forEach(t => db.prepare(`DELETE FROM ${t} WHERE account_id=?`).run(id));
  db.prepare('DELETE FROM accounts WHERE id=?').run(id);
  res.json({ success: true });
});

app.post('/api/admin/accounts/:id/extend', auth, superOnly, (req, res) => {
  const { days } = req.body;
  const account = db.prepare('SELECT * FROM accounts WHERE id=?').get(req.params.id);
  if (!account) return res.status(404).json({ error: 'Compte introuvable' });
  const base = account.expires_at && new Date(account.expires_at) > new Date() ? new Date(account.expires_at) : new Date();
  base.setDate(base.getDate() + (parseInt(days) || 30));
  db.prepare('UPDATE accounts SET expires_at=? WHERE id=?').run(base.toISOString().split('T')[0], req.params.id);
  res.json({ success: true, expires_at: base.toISOString().split('T')[0] });
});

// ─── GENERIC CRUD FACTORY ─────────────────────────────────────────────────────
function crudRoutes(app, tableName, auth) {
  // GET ALL
  app.get(`/api/${tableName}`, auth, (req, res) => {
    const rows = db.prepare(`SELECT * FROM ${tableName} WHERE account_id=? ORDER BY id DESC`).all(req.account.id);
    res.json(rows);
  });
  // GET ONE
  app.get(`/api/${tableName}/:id`, auth, (req, res) => {
    const row = db.prepare(`SELECT * FROM ${tableName} WHERE id=? AND account_id=?`).get(req.params.id, req.account.id);
    if (!row) return res.status(404).json({ error: 'Non trouvé' });
    res.json(row);
  });
  // DELETE
  app.delete(`/api/${tableName}/:id`, auth, (req, res) => {
    db.prepare(`DELETE FROM ${tableName} WHERE id=? AND account_id=?`).run(req.params.id, req.account.id);
    res.json({ success: true });
  });
}

crudRoutes(app, 'vehicles', auth);
crudRoutes(app, 'drivers', auth);
crudRoutes(app, 'missions', auth);
crudRoutes(app, 'invoices', auth);
crudRoutes(app, 'fuels', auth);
crudRoutes(app, 'expenses', auth);
crudRoutes(app, 'maintenances', auth);
crudRoutes(app, 'leaves', auth);
crudRoutes(app, 'alerts', auth);

// ─── VEHICLES ─────────────────────────────────────────────────────────────────
app.post('/api/vehicles', auth, (req, res) => {
  const { plate, model, type, km, fuel, status, insurance, maintenance, vignette, year, color } = req.body;
  if (!plate || !model) return res.status(400).json({ error: 'Plaque et modèle requis' });
  const r = db.prepare(`INSERT INTO vehicles (account_id,plate,model,type,km,fuel,status,insurance,maintenance,vignette,year,color)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(req.account.id, plate, model, type||'Camion Semi', km||0, fuel||100, status||'disponible', insurance||'', maintenance||'', vignette||'', year||2020, color||'');
  res.json({ success: true, id: r.lastInsertRowid });
});
app.put('/api/vehicles/:id', auth, (req, res) => {
  const { plate, model, type, km, fuel, status, insurance, maintenance, vignette, year, color } = req.body;
  db.prepare(`UPDATE vehicles SET plate=?,model=?,type=?,km=?,fuel=?,status=?,insurance=?,maintenance=?,vignette=?,year=?,color=? WHERE id=? AND account_id=?`
  ).run(plate, model, type, km||0, fuel||100, status, insurance||'', maintenance||'', vignette||'', year||2020, color||'', req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── DRIVERS ──────────────────────────────────────────────────────────────────
app.post('/api/drivers', auth, (req, res) => {
  const { name, cin, phone, license, city, salary, status, dob, hire } = req.body;
  if (!name) return res.status(400).json({ error: 'Nom requis' });
  const r = db.prepare(`INSERT INTO drivers (account_id,name,cin,phone,license,city,salary,status,dob,hire)
    VALUES (?,?,?,?,?,?,?,?,?,?)`).run(req.account.id, name, cin||'', phone||'', license||'C+E', city||'', salary||0, status||'actif', dob||'', hire||'');
  res.json({ success: true, id: r.lastInsertRowid });
});
app.put('/api/drivers/:id', auth, (req, res) => {
  const { name, cin, phone, license, city, salary, status, dob, hire } = req.body;
  db.prepare(`UPDATE drivers SET name=?,cin=?,phone=?,license=?,city=?,salary=?,status=?,dob=?,hire=? WHERE id=? AND account_id=?`
  ).run(name, cin||'', phone||'', license||'C+E', city||'', salary||0, status||'actif', dob||'', hire||'', req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── MISSIONS ─────────────────────────────────────────────────────────────────
app.post('/api/missions', auth, (req, res) => {
  const { client, origin, destination, driver_id, vehicle_id, status, date, distance, amount, notes } = req.body;
  if (!client || !origin || !destination) return res.status(400).json({ error: 'Client, départ et arrivée requis' });
  const id = 'MSN-' + Date.now().toString(36).toUpperCase();
  db.prepare(`INSERT INTO missions (id,account_id,client,origin,destination,driver_id,vehicle_id,status,date,distance,amount,notes)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, req.account.id, client, origin, destination, driver_id||null, vehicle_id||null, status||'planifie', date||new Date().toISOString().split('T')[0], distance||0, amount||0, notes||'');
  res.json({ success: true, id });
});
app.put('/api/missions/:id', auth, (req, res) => {
  const { client, origin, destination, driver_id, vehicle_id, status, date, distance, amount, notes } = req.body;
  db.prepare(`UPDATE missions SET client=?,origin=?,destination=?,driver_id=?,vehicle_id=?,status=?,date=?,distance=?,amount=?,notes=? WHERE id=? AND account_id=?`
  ).run(client, origin, destination, driver_id||null, vehicle_id||null, status, date, distance||0, amount||0, notes||'', req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── INVOICES ─────────────────────────────────────────────────────────────────
app.post('/api/invoices', auth, (req, res) => {
  const { client, amount, status, date, due, notes } = req.body;
  if (!client || !amount) return res.status(400).json({ error: 'Client et montant requis' });
  const id = 'FAC-' + Date.now().toString(36).toUpperCase();
  db.prepare(`INSERT INTO invoices (id,account_id,client,amount,status,date,due,notes)
    VALUES (?,?,?,?,?,?,?,?)`).run(id, req.account.id, client, amount, status||'en_attente', date||new Date().toISOString().split('T')[0], due||'', notes||'');
  res.json({ success: true, id });
});
app.put('/api/invoices/:id', auth, (req, res) => {
  const { client, amount, status, date, due, notes } = req.body;
  db.prepare(`UPDATE invoices SET client=?,amount=?,status=?,date=?,due=?,notes=? WHERE id=? AND account_id=?`
  ).run(client, amount, status, date, due||'', notes||'', req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── FUELS ────────────────────────────────────────────────────────────────────
app.post('/api/fuels', auth, (req, res) => {
  const { vehicle_id, date, litres, price_per_l, station, km } = req.body;
  if (!vehicle_id || !litres) return res.status(400).json({ error: 'Véhicule et litres requis' });
  const r = db.prepare(`INSERT INTO fuels (account_id,vehicle_id,date,litres,price_per_l,station,km)
    VALUES (?,?,?,?,?,?,?)`).run(req.account.id, vehicle_id, date||new Date().toISOString().split('T')[0], litres, price_per_l||14.50, station||'', km||0);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.put('/api/fuels/:id', auth, (req, res) => {
  const { vehicle_id, date, litres, price_per_l, station, km } = req.body;
  db.prepare(`UPDATE fuels SET vehicle_id=?,date=?,litres=?,price_per_l=?,station=?,km=? WHERE id=? AND account_id=?`
  ).run(vehicle_id, date, litres, price_per_l||14.50, station||'', km||0, req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── EXPENSES ─────────────────────────────────────────────────────────────────
app.post('/api/expenses', auth, (req, res) => {
  const { vehicle_id, type, amount, date, description, justif } = req.body;
  const r = db.prepare(`INSERT INTO expenses (account_id,vehicle_id,type,amount,date,description,justif)
    VALUES (?,?,?,?,?,?,?)`).run(req.account.id, vehicle_id||null, type||'Autre', amount||0, date||new Date().toISOString().split('T')[0], description||'', justif?1:0);
  res.json({ success: true, id: r.lastInsertRowid });
});
app.put('/api/expenses/:id', auth, (req, res) => {
  const { vehicle_id, type, amount, date, description, justif } = req.body;
  db.prepare(`UPDATE expenses SET vehicle_id=?,type=?,amount=?,date=?,description=?,justif=? WHERE id=? AND account_id=?`
  ).run(vehicle_id||null, type||'Autre', amount||0, date, description||'', justif?1:0, req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── MAINTENANCES ─────────────────────────────────────────────────────────────
app.post('/api/maintenances', auth, (req, res) => {
  const { vehicle_id, type, date, km, cost, status, notes, technicien } = req.body;
  const r = db.prepare(`INSERT INTO maintenances (account_id,vehicle_id,type,date,km,cost,status,notes,technicien)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(req.account.id, vehicle_id||null, type||'Vidange', date||'', km||0, cost||0, status||'planifie', notes||'', technicien||'');
  res.json({ success: true, id: r.lastInsertRowid });
});
app.put('/api/maintenances/:id', auth, (req, res) => {
  const { vehicle_id, type, date, km, cost, status, notes, technicien } = req.body;
  db.prepare(`UPDATE maintenances SET vehicle_id=?,type=?,date=?,km=?,cost=?,status=?,notes=?,technicien=? WHERE id=? AND account_id=?`
  ).run(vehicle_id||null, type, date, km||0, cost||0, status, notes||'', technicien||'', req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── LEAVES ───────────────────────────────────────────────────────────────────
app.post('/api/leaves', auth, (req, res) => {
  const { driver_id, from_date, to_date, type, status, notes } = req.body;
  const r = db.prepare(`INSERT INTO leaves (account_id,driver_id,from_date,to_date,type,status,notes)
    VALUES (?,?,?,?,?,?,?)`).run(req.account.id, driver_id||null, from_date||'', to_date||'', type||'Conge annuel', status||'en_attente', notes||'');
  res.json({ success: true, id: r.lastInsertRowid });
});
app.put('/api/leaves/:id', auth, (req, res) => {
  const { status, notes } = req.body;
  db.prepare(`UPDATE leaves SET status=?,notes=? WHERE id=? AND account_id=?`
  ).run(status, notes||'', req.params.id, req.account.id);
  res.json({ success: true });
});

// ─── ALERTS ───────────────────────────────────────────────────────────────────
app.post('/api/alerts', auth, (req, res) => {
  const { type, title, desc } = req.body;
  if (!title) return res.status(400).json({ error: 'Titre requis' });
  const r = db.prepare(`INSERT INTO alerts (account_id,type,title,desc) VALUES (?,?,?,?)`
  ).run(req.account.id, type||'info', title, desc||'');
  res.json({ success: true, id: r.lastInsertRowid });
});
app.put('/api/alerts/:id', auth, (req, res) => {
  db.prepare(`UPDATE alerts SET read=1 WHERE id=? AND account_id=?`).run(req.params.id, req.account.id);
  res.json({ success: true });
});
app.put('/api/alerts', auth, (req, res) => {
  db.prepare(`UPDATE alerts SET read=1 WHERE account_id=?`).run(req.account.id);
  res.json({ success: true });
});

// ─── STATS (Dashboard) ───────────────────────────────────────────────────────
app.get('/api/stats', auth, (req, res) => {
  const aid = req.account.id;
  const vehicles = db.prepare('SELECT COUNT(*) as c FROM vehicles WHERE account_id=?').get(aid).c;
  const drivers = db.prepare('SELECT COUNT(*) as c FROM drivers WHERE account_id=?').get(aid).c;
  const missions = db.prepare('SELECT COUNT(*) as c FROM missions WHERE account_id=?').get(aid).c;
  const activeMissions = db.prepare("SELECT COUNT(*) as c FROM missions WHERE account_id=? AND status='en_cours'").get(aid).c;
  const revenue = db.prepare("SELECT COALESCE(SUM(amount),0) as s FROM invoices WHERE account_id=? AND status='paye'").get(aid).s;
  const pending = db.prepare("SELECT COALESCE(SUM(amount),0) as s FROM invoices WHERE account_id=? AND status='en_attente'").get(aid).s;
  const unreadAlerts = db.prepare('SELECT COUNT(*) as c FROM alerts WHERE account_id=? AND read=0').get(aid).c;
  res.json({ vehicles, drivers, missions, activeMissions, revenue, pending, unreadAlerts });
});

// ─── ADMIN STATS ──────────────────────────────────────────────────────────────
app.get('/api/admin/stats', auth, superOnly, (req, res) => {
  const total = db.prepare("SELECT COUNT(*) as c FROM accounts WHERE role='client'").get().c;
  const active = db.prepare("SELECT COUNT(*) as c FROM accounts WHERE role='client' AND status='active'").get().c;
  const expired = db.prepare("SELECT COUNT(*) as c FROM accounts WHERE role='client' AND expires_at < datetime('now')").get().c;
  const revenue30 = db.prepare("SELECT COUNT(*) as c FROM accounts WHERE role='client' AND plan='month'").get().c;
  const revenueYear = db.prepare("SELECT COUNT(*) as c FROM accounts WHERE role='client' AND plan='year'").get().c;
  const revenueLife = db.prepare("SELECT COUNT(*) as c FROM accounts WHERE role='client' AND plan='life'").get().c;
  const totalRevenue = (revenue30 * 499) + (revenueYear * 4990) + (revenueLife * 19999);
  res.json({ total, active, expired, revenue30, revenueYear, revenueLife, totalRevenue });
});

// ─── SPA FALLBACK ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ GFM Server running on port ${PORT}`);
});
