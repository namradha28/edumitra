require('dotenv').config();
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
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

// Serves index.html, admin.html, dashboard.html, and everything else in /public
app.use(express.static(path.join(__dirname, 'public')));

/* ════════════════════════ RATE LIMITERS ════════════════════════ */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many signup attempts. Please try again later.' }
});

/* ════════════════════════ ZEPTO MAIL (transactional email) ════════════════════════ */

const mailer = nodemailer.createTransport({
  host: process.env.ZEPTO_HOST || 'smtp.zeptomail.in',
  port: parseInt(process.env.ZEPTO_PORT || '587', 10),
  secure: false,                  // STARTTLS on 587
  auth: {
    user: process.env.ZEPTO_USER,
    pass: process.env.ZEPTO_PASS
  }
});

// Verify SMTP credentials on startup so we know early if creds are wrong
if (process.env.ZEPTO_USER && process.env.ZEPTO_PASS) {
  mailer.verify().then(
    () => console.log('[mail] Zepto Mail SMTP ready'),
    err => console.warn('[mail] Zepto Mail not reachable:', err.message)
  );
} else {
  console.warn('[mail] ZEPTO_USER / ZEPTO_PASS not set — emails will be skipped');
}

async function sendEmail({ to, subject, html }) {
  if (!process.env.ZEPTO_USER) {
    console.warn('[mail] skipping email to', to, '(no SMTP credentials)');
    return;
  }
  try {
    await mailer.sendMail({
      from: process.env.ZEPTO_FROM || 'info@edumitra.co',
      to, subject, html
    });
    console.log('[mail] sent to', to, '·', subject);
  } catch (err) {
    console.error('[mail] failed to', to, '·', err.message);
  }
}

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

function publicUser(u) {
  if (!u) return u;
  const { passwordHash, ...safe } = u;
  return safe;
}

/* ════════════════════════ PASSWORD HASHING ════════════════════════ */

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

/* ════════════════════════ EMAIL TEMPLATES ════════════════════════
   Inline minimal HTML for now. Move to a templates folder when you have time. */

function welcomeEmailHtml(name) {
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">Welcome to EduMitra</h2>
    <p style="line-height:1.6;font-size:14.5px;">Hi ${escapeForEmail(name || 'there')},</p>
    <p style="line-height:1.6;font-size:14.5px;">Thank you for signing up. Your registration has been received and our team will review it shortly.</p>
    <p style="line-height:1.6;font-size:14.5px;">Once approved, you will receive another email and can access your student dashboard to manage your counselling journey.</p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
  <p style="text-align:center;color:#6b7280;font-size:12px;margin-top:24px;">EduMitra · Education Counselling for Studying Abroad, Placements, and Job Switching</p>
</body></html>`;
}

function approvalEmailHtml(name, dashboardUrl) {
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">Your account is approved</h2>
    <p style="line-height:1.6;font-size:14.5px;">Hi ${escapeForEmail(name || 'there')},</p>
    <p style="line-height:1.6;font-size:14.5px;">Good news — your EduMitra account has been approved by our team. You can now access your student dashboard.</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="${dashboardUrl}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">Go to my dashboard</a>
    </p>
    <p style="line-height:1.6;font-size:14.5px;color:#6b7280;">If the button does not work, paste this link into your browser:<br><a href="${dashboardUrl}" style="color:#c8953a;word-break:break-all;">${dashboardUrl}</a></p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
  <p style="text-align:center;color:#6b7280;font-size:12px;margin-top:24px;">EduMitra · Education Counselling for Studying Abroad, Placements, and Job Switching</p>
</body></html>`;
}

function escapeForEmail(str) {
  return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
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
    const isNew = !existing;
    const user = upsertUser({
      name: profile.name,
      email: profile.email,
      picture: profile.picture,
      provider: 'google',
      approved: existing ? existing.approved : false,
      registeredAt: existing ? existing.registeredAt : Date.now()
    });
    req.session.user = { role: 'student', ...publicUser(user) };

    if (isNew) {
      sendEmail({
        to: user.email,
        subject: 'Welcome to EduMitra',
        html: welcomeEmailHtml(user.name)
      });
    }

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
    const isNew = !existing;
    const user = upsertUser({
      name: profile.name,
      email: profile.email,
      picture: profile.picture,
      provider: 'linkedin',
      approved: existing ? existing.approved : false,
      registeredAt: existing ? existing.registeredAt : Date.now()
    });
    req.session.user = { role: 'student', ...publicUser(user) };

    if (isNew) {
      sendEmail({
        to: user.email,
        subject: 'Welcome to EduMitra',
        html: welcomeEmailHtml(user.name)
      });
    }

    res.redirect(`${FRONTEND_URL}/?auth=success`);
  } catch (err) {
    console.error('LinkedIn OAuth error:', err);
    res.redirect(`${FRONTEND_URL}/?auth=error&reason=linkedin_failed`);
  }
});

/* ════════════════════════ STUDENT AUTH (email + password) ════════════════════════ */

app.post('/api/auth/signup', signupLimiter, (req, res) => {
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

  sendEmail({
    to: user.email,
    subject: 'Welcome to EduMitra',
    html: welcomeEmailHtml(user.name)
  });

  res.json({ ok: true, user: req.session.user });
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
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

app.post('/api/admin/login', loginLimiter, (req, res) => {
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
  const wasAlreadyApproved = users[key].approved === true;
  const verifyData = { ...(users[key].verifyData || {}), verificationStatus: 'approved' };
  const updated = upsertUser({ email: key, approved: true, verifyData, adminNote: req.body?.note || '' });

  if (!wasAlreadyApproved) {
    sendEmail({
      to: updated.email,
      subject: 'Your EduMitra account is approved',
      html: approvalEmailHtml(updated.name, `${FRONTEND_URL}/dashboard.html`)
    });
  }

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
