require('dotenv').config();
const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || `http://localhost:${PORT}`;

const SUPERADMIN_EMAIL    = (process.env.SUPERADMIN_EMAIL || '').toLowerCase();
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || '';

app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax'
    // secure: true   <-- uncomment once your site is served over HTTPS
  }
}));

// Serves index.html, admin.html, and everything else in /public
app.use(express.static(path.join(__dirname, 'public')));

/* ════════════════════════ TINY JSON-FILE "DATABASE" ════════════════════════
   Fine for getting started and testing. Swap for a real database
   (Postgres, MongoDB, Firebase, etc.) before you have real users at scale —
   concurrent writes to a JSON file are not safe under real traffic. */

const USERS_FILE  = path.join(__dirname, 'data', 'users.json');
const ADMINS_FILE = path.join(__dirname, 'data', 'admins.json');

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return {}; }
}
function writeJSON(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
const readUsers   = () => readJSON(USERS_FILE);
const writeUsers  = (u) => writeJSON(USERS_FILE, u);
const readAdmins  = () => readJSON(ADMINS_FILE);
const writeAdmins = (a) => writeJSON(ADMINS_FILE, a);

function upsertUser(profile) {
  const users = readUsers();
  const key = profile.email.toLowerCase();
  users[key] = { ...users[key], ...profile, email: key, updatedAt: new Date().toISOString() };
  writeUsers(users);
  return users[key];
}

// Strip fields the browser should never receive
function publicUser(u) {
  if (!u) return u;
  const { passwordHash, ...safe } = u;
  return safe;
}

/* ════════════════════════ PASSWORD HASHING ════════════════════════
   No extra dependency needed — Node's built-in crypto.scrypt is a solid,
   well-reviewed choice for this. Stored as "salt:hash" hex. */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const attempt = crypto.scryptSync(password, salt, 64).toString('hex');
  try { return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex')); }
  catch (e) { return false; }
}

/* ════════════════════════ ROLE MIDDLEWARE ════════════════════════ */

function requireAdmin(req, res, next) {
  if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'superadmin')) return next();
  res.status(401).json({ error: 'Not authorized.' });
}
function requireSuperAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'superadmin') return next();
  res.status(401).json({ error: 'Super admin access only.' });
}

/* ════════════════════════ GOOGLE OAUTH ════════════════════════ */

app.get('/auth/google', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account'
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || state !== req.session.oauthState) {
      return res.redirect(`${FRONTEND_URL}/?auth=error&reason=state_mismatch`);
    }
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('Google did not return an access token');

    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json();

    const existing = readUsers()[profile.email.toLowerCase()];
    const user = upsertUser({
      name: profile.name,
      email: profile.email,
      picture: profile.picture,
      provider: 'google',
      approved: existing ? existing.approved : false,
      registeredAt: existing ? existing.registeredAt : Date.now()
    });
    req.session.user = { role: 'student', ...publicUser(user) };

    res.redirect(`${FRONTEND_URL}/?auth=success`);
  } catch (err) {
    console.error('Google OAuth error:', err);
    res.redirect(`${FRONTEND_URL}/?auth=error&reason=google_failed`);
  }
});

/* ════════════════════════ LINKEDIN OAUTH ════════════════════════ */

app.get('/auth/linkedin', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: process.env.LINKEDIN_CLIENT_ID,
    redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid profile email',
    state
  });
  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params}`);
});

app.get('/auth/linkedin/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || state !== req.session.oauthState) {
      return res.redirect(`${FRONTEND_URL}/?auth=error&reason=state_mismatch`);
    }
    const tokenRes = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.LINKEDIN_CLIENT_ID,
        client_secret: process.env.LINKEDIN_CLIENT_SECRET,
        redirect_uri: process.env.LINKEDIN_REDIRECT_URI
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('LinkedIn did not return an access token');

    const profileRes = await fetch('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileRes.json();

    const existing = readUsers()[profile.email.toLowerCase()];
    const user = upsertUser({
      name: profile.name,
      email: profile.email,
      picture: profile.picture,
      provider: 'linkedin',
      approved: existing ? existing.approved : false,
      registeredAt: existing ? existing.registeredAt : Date.now()
    });
    req.session.user = { role: 'student', ...publicUser(user) };

    res.redirect(`${FRONTEND_URL}/?auth=success`);
  } catch (err) {
    console.error('LinkedIn OAuth error:', err);
    res.redirect(`${FRONTEND_URL}/?auth=error&reason=linkedin_failed`);
  }
});

/* ════════════════════════ STUDENT AUTH (email + password) ════════════════════════ */

app.post('/api/auth/signup', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid name and email.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const key = email.toLowerCase();
  if (readUsers()[key]) return res.status(409).json({ error: 'An account already exists for this email. Please sign in instead.' });

  const user = upsertUser({
    name, email,
    passwordHash: hashPassword(password),
    provider: 'password',
    approved: false,
    registeredAt: Date.now()
  });
  req.session.user = { role: 'student', ...publicUser(user) };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = readUsers()[(email || '').toLowerCase()];
  const GENERIC = 'Invalid email or password.';
  if (!user) return res.status(401).json({ error: GENERIC });
  if (!user.passwordHash) return res.status(401).json({ error: GENERIC });
  if (!verifyPassword(password || '', user.passwordHash)) return res.status(401).json({ error: GENERIC });

  req.session.user = { role: 'student', ...publicUser(user) };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/auth/verify', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') return res.status(401).json({ error: 'Please sign in first.' });

  const verifyData = { ...req.body, submittedAt: Date.now(), verificationStatus: 'pending' };
  const user = upsertUser({ email: req.session.user.email, verifyData });
  req.session.user = { role: 'student', ...publicUser(user) };
  res.json({ ok: true, user: req.session.user });
});

app.get('/api/me', (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, user: req.session.user });
  res.json({ loggedIn: false });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => res.redirect(`${FRONTEND_URL}/`));
});

/* ════════════════════════ ADMIN ════════════════════════ */

app.post('/api/admin/login', (req, res) => {
  const { email, password } = req.body || {};
  const key = (email || '').toLowerCase();
  const GENERIC = 'Invalid email or password.';

  if (SUPERADMIN_EMAIL && key === SUPERADMIN_EMAIL) {
    if (password === SUPERADMIN_PASSWORD) {
      req.session.user = { role: 'superadmin', email: key, name: 'Super Admin' };
      return res.json({ ok: true, user: req.session.user });
    }
    return res.status(401).json({ error: GENERIC });
  }

  const admin = readAdmins()[key];
  if (!admin) return res.status(401).json({ error: GENERIC });
  if (!verifyPassword(password || '', admin.passwordHash)) return res.status(401).json({ error: GENERIC });

  req.session.user = { role: 'admin', email: key, name: admin.name };
  res.json({ ok: true, user: req.session.user });
});

app.get('/api/admin/me', (req, res) => {
  if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'superadmin')) {
    return res.json({ loggedIn: true, user: req.session.user });
  }
  res.json({ loggedIn: false });
});

app.get('/api/admin/students', requireAdmin, (req, res) => {
  const users = readUsers();
  const list = Object.values(users).map(publicUser);
  res.json({ students: list });
});

app.post('/api/admin/students/:email/approve', requireAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const users = readUsers();
  if (!users[key]) return res.status(404).json({ error: 'Student not found.' });
  const verifyData = { ...(users[key].verifyData || {}), verificationStatus: 'approved' };
  upsertUser({ email: key, approved: true, verifyData, adminNote: req.body?.note || '' });
  res.json({ ok: true });
});

app.post('/api/admin/students/:email/reject', requireAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const users = readUsers();
  if (!users[key]) return res.status(404).json({ error: 'Student not found.' });
  const verifyData = { ...(users[key].verifyData || {}), verificationStatus: 'rejected' };
  upsertUser({ email: key, approved: false, verifyData, adminNote: req.body?.note || '' });
  res.json({ ok: true });
});

app.get('/api/admin/analytics', requireAdmin, (req, res) => {
  const users = Object.values(readUsers());
  let pending = 0, approved = 0, rejected = 0;
  users.forEach(u => {
    const status = u.approved ? 'approved' : (u.verifyData?.verificationStatus === 'rejected' ? 'rejected' : 'pending');
    if (status === 'approved') approved++;
    else if (status === 'rejected') rejected++;
    else pending++;
  });

  // Signups per day for the last 14 days
  const days = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    days.push({ date: d.toISOString().slice(0, 10), count: 0 });
  }
  users.forEach(u => {
    if (!u.registeredAt) return;
    const day = new Date(u.registeredAt).toISOString().slice(0, 10);
    const bucket = days.find(d => d.date === day);
    if (bucket) bucket.count++;
  });

  const recent = users
    .filter(u => u.registeredAt)
    .sort((a, b) => b.registeredAt - a.registeredAt)
    .slice(0, 8)
    .map(publicUser);

  res.json({ total: users.length, pending, approved, rejected, signupsByDay: days, recent });
});

/* ════════════════════════ SUPER ADMIN — manage admin accounts ════════════════════════ */

app.get('/api/superadmin/admins', requireSuperAdmin, (req, res) => {
  const admins = Object.values(readAdmins()).map(({ passwordHash, ...safe }) => safe);
  res.json({ admins, superAdminEmail: SUPERADMIN_EMAIL });
});

app.post('/api/superadmin/admins', requireSuperAdmin, (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid name and email.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const key = email.toLowerCase();
  if (key === SUPERADMIN_EMAIL) return res.status(409).json({ error: 'That email is reserved for the super admin account.' });
  const admins = readAdmins();
  if (admins[key]) return res.status(409).json({ error: 'An admin with this email already exists.' });

  admins[key] = { name, email: key, passwordHash: hashPassword(password), createdAt: Date.now(), createdBy: req.session.user.email };
  writeAdmins(admins);
  res.json({ ok: true });
});

app.delete('/api/superadmin/admins/:email', requireSuperAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const admins = readAdmins();
  if (!admins[key]) return res.status(404).json({ error: 'Admin not found.' });
  delete admins[key];
  writeAdmins(admins);
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));