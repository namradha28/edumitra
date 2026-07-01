require('dotenv').config();
const express = require('express');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || `http://localhost:${PORT}`;

const SUPERADMIN_EMAIL    = (process.env.SUPERADMIN_EMAIL || '').toLowerCase();
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || '';

// Required when running behind a reverse proxy (Railway, Render, etc.) so
// express-session can correctly set "secure" cookies over HTTPS.
app.set('trust proxy', 1);

app.use(express.json());
app.use(session({
  store: new FileStore({
    path: path.join(__dirname, 'data', 'sessions'),
    ttl: 7 * 24 * 60 * 60,           // 7 days, matches cookie maxAge below
    retries: 0,
    logFn: function () {}             // silence noisy file-store logging
  }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days — was unset before, so every cookie died with the browser session
    secure: process.env.NODE_ENV === 'production'
  }
}));
app.use(express.static(path.join(__dirname, 'public')));

/* ════════════════════════ RATE LIMITERS ════════════════════════ */

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many signup attempts. Please try again later.' }
});

/* ════════════════════════ ZEPTO MAIL ════════════════════════ */

const mailer = nodemailer.createTransport({
  host: process.env.ZEPTO_HOST || 'smtp.zeptomail.in',
  port: parseInt(process.env.ZEPTO_PORT || '587', 10),
  secure: false,
  auth: { user: process.env.ZEPTO_USER, pass: process.env.ZEPTO_PASS }
});

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

/* ════════════════════════ JSON-FILE "DATABASE" ════════════════════════ */

const USERS_FILE       = path.join(__dirname, 'data', 'users.json');
const ADMINS_FILE      = path.join(__dirname, 'data', 'admins.json');
const COUNSELLORS_FILE = path.join(__dirname, 'data', 'counsellors.json');
const SLOTS_FILE       = path.join(__dirname, 'data', 'slots.json');
const RESET_TOKENS_FILE = path.join(__dirname, 'data', 'reset-tokens.json');

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return {}; }
}
function writeJSON(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
const readUsers        = () => readJSON(USERS_FILE);
const writeUsers       = (u) => writeJSON(USERS_FILE, u);
const readAdmins       = () => readJSON(ADMINS_FILE);
const writeAdmins      = (a) => writeJSON(ADMINS_FILE, a);
const readCounsellors  = () => readJSON(COUNSELLORS_FILE);
const writeCounsellors = (c) => writeJSON(COUNSELLORS_FILE, c);
const readSlots        = () => readJSON(SLOTS_FILE);
const writeSlots       = (s) => writeJSON(SLOTS_FILE, s);
const readResetTokens  = () => readJSON(RESET_TOKENS_FILE);
const writeResetTokens = (t) => writeJSON(RESET_TOKENS_FILE, t);

// Finds an account by email across all three "JSON-file databases".
// Superadmin is intentionally excluded — that login is env-var based,
// not a stored record, so it can't be reset through this flow.
function findAccountByEmail(email) {
  const key = (email || '').toLowerCase();
  const users = readUsers();
  if (users[key] && users[key].passwordHash) return { role: 'student', key, read: readUsers, write: writeUsers };
  const admins = readAdmins();
  if (admins[key]) return { role: 'admin', key, read: readAdmins, write: writeAdmins };
  const counsellors = readCounsellors();
  if (counsellors[key]) return { role: 'counsellor', key, read: readCounsellors, write: writeCounsellors };
  return null;
}

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

/* ════════════════════════ PASSWORD HASHING + GENERATION ════════════════════════ */

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
function generatePassword() {
  const upper = 'ABCDEFGHJKMNPQRSTUVWXYZ';
  const lower = 'abcdefghjkmnpqrstuvwxyz';
  const digit = '23456789';
  const symbol = '!@#$%&*';
  const all = upper + lower + digit + symbol;
  let pw = [
    upper[crypto.randomInt(0, upper.length)],
    lower[crypto.randomInt(0, lower.length)],
    digit[crypto.randomInt(0, digit.length)],
    symbol[crypto.randomInt(0, symbol.length)],
  ];
  for (let i = 0; i < 8; i++) pw.push(all[crypto.randomInt(0, all.length)]);
  for (let i = pw.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [pw[i], pw[j]] = [pw[j], pw[i]];
  }
  return pw.join('');
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
function requireCounsellor(req, res, next) {
  if (req.session.user && req.session.user.role === 'counsellor') return next();
  res.status(401).json({ error: 'Counsellor access only.' });
}
function requireStudent(req, res, next) {
  if (req.session.user && req.session.user.role === 'student') return next();
  res.status(401).json({ error: 'Please sign in first.' });
}

/* ════════════════════════ EMAIL TEMPLATES ════════════════════════ */

function escapeForEmail(str) {
  return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function welcomeEmailHtml(name, pendingUrl) {
  const url = pendingUrl || `${FRONTEND_URL}/pending.html`;
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">Welcome to EduMitra</h2>
    <p style="line-height:1.6;font-size:14.5px;">Hi ${escapeForEmail(name || 'there')},</p>
    <p style="line-height:1.6;font-size:14.5px;">Thank you for signing up. Your registration has been received and our admin team is currently reviewing it — this usually takes less than 24 hours.</p>
    <p style="line-height:1.6;font-size:14.5px;">Once approved, you will receive a second email with a direct link to your student dashboard.</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="${url}" style="display:inline-block;padding:12px 28px;background:#c8953a;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">Check verification status</a>
    </p>
    <p style="line-height:1.6;font-size:13px;color:#6b7280;">Make sure to check your spam folder for future emails from us.</p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
</body></html>`;
}

function adminNewSignupEmailHtml(studentName, studentEmail) {
  const adminUrl = `${FRONTEND_URL}/admin.html`;
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">New student pending approval</h2>
    <p style="line-height:1.6;font-size:14.5px;">A new student has signed up and is waiting for your approval.</p>
    <div style="background:#faf7f2;border:1px solid #eaedf5;border-radius:10px;padding:20px;margin:22px 0;">
      <p style="margin:0 0 6px;font-size:13px;color:#6b7280;text-transform:uppercase;letter-spacing:0.6px;font-weight:700;">Student details</p>
      <p style="margin:6px 0 0;font-size:14.5px;"><strong>Name:</strong> ${escapeForEmail(studentName || '—')}</p>
      <p style="margin:6px 0 0;font-size:14.5px;"><strong>Email:</strong> ${escapeForEmail(studentEmail)}</p>
    </div>
    <p style="text-align:center;margin:28px 0;">
      <a href="${adminUrl}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">Review in Admin Panel →</a>
    </p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— EduMitra System</p>
  </div>
</body></html>`;
}

function approvalEmailHtml(name, dashboardUrl) {
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">Your account is approved</h2>
    <p style="line-height:1.6;font-size:14.5px;">Hi ${escapeForEmail(name || 'there')},</p>
    <p style="line-height:1.6;font-size:14.5px;">Good news — your EduMitra account has been approved. You can now access your student dashboard.</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="${dashboardUrl}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">Go to my dashboard</a>
    </p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
</body></html>`;
}

function counsellorWelcomeEmailHtml(name, email, password, loginUrl) {
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">Welcome to EduMitra, ${escapeForEmail(name)}</h2>
    <p style="line-height:1.6;font-size:14.5px;">Your counsellor account on EduMitra has been created.</p>
    <div style="background:#faf7f2;border:1px solid #eaedf5;border-radius:10px;padding:20px;margin:22px 0;">
      <p style="margin:0 0 10px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.6px;color:#6b7280;">Your login details</p>
      <p style="margin:0 0 6px;font-size:14.5px;"><strong>Email:</strong> ${escapeForEmail(email)}</p>
      <p style="margin:0;font-size:14.5px;"><strong>Temporary password:</strong> <code style="background:#fff;padding:3px 8px;border-radius:4px;border:1px solid #eaedf5;font-size:14px;">${escapeForEmail(password)}</code></p>
    </div>
    <p style="text-align:center;margin:28px 0;">
      <a href="${loginUrl}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">Log in to counsellor portal</a>
    </p>
    <p style="line-height:1.6;font-size:13px;color:#6b7280;">For your security, please change this password after your first login from My Profile in the counsellor dashboard.</p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
</body></html>`;
}

function bookingEmailHtml({ studentName, counsellorName, date, startTime, endTime, label, meetLink }) {
  const niceDate = new Date(date + 'T00:00:00').toLocaleDateString('en-IN', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">Your counselling session is booked</h2>
    <p style="line-height:1.6;font-size:14.5px;">Hi ${escapeForEmail(studentName)},</p>
    <p style="line-height:1.6;font-size:14.5px;">Your slot with <strong>${escapeForEmail(counsellorName)}</strong> has been confirmed on Google Calendar. A Google Meet link has been generated for the call.</p>
    <div style="background:#faf7f2;border:1px solid #eaedf5;border-radius:10px;padding:20px;margin:22px 0;">
      <p style="margin:0 0 6px;font-size:13px;color:#6b7280;text-transform:uppercase;letter-spacing:0.6px;font-weight:700;">Session details</p>
      <p style="margin:6px 0 0;font-size:14.5px;"><strong>Date:</strong> ${niceDate}</p>
      <p style="margin:6px 0 0;font-size:14.5px;"><strong>Time:</strong> ${startTime} – ${endTime} (IST)</p>
      <p style="margin:6px 0 0;font-size:14.5px;"><strong>Topic:</strong> ${escapeForEmail(label || 'General Counselling')}</p>
    </div>
    <p style="text-align:center;margin:28px 0;">
      <a href="${meetLink}" style="display:inline-block;padding:13px 32px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">Join Google Meet</a>
    </p>
    <p style="line-height:1.6;font-size:13px;color:#6b7280;">If the button does not work, paste this into your browser:<br><a href="${meetLink}" style="color:#c8953a;word-break:break-all;">${meetLink}</a></p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
</body></html>`;
}

function resetPasswordEmailHtml(name, resetUrl) {
  return `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="font-family:'Playfair Display',Georgia,serif;color:#0a1628;margin:0 0 12px;">Reset your password</h2>
    <p style="line-height:1.6;font-size:14.5px;">Hi ${escapeForEmail(name || 'there')},</p>
    <p style="line-height:1.6;font-size:14.5px;">We received a request to reset your EduMitra password. Click the button below to set a new one. This link expires in 1 hour.</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="${resetUrl}" style="display:inline-block;padding:13px 32px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">Reset password</a>
    </p>
    <p style="line-height:1.6;font-size:13px;color:#6b7280;">If the button does not work, paste this into your browser:<br><a href="${resetUrl}" style="color:#c8953a;word-break:break-all;">${resetUrl}</a></p>
    <p style="line-height:1.6;font-size:13px;color:#6b7280;">If you did not request this, you can safely ignore this email — your password will not be changed.</p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
</body></html>`;
}

/* ════════════════════════ GOOGLE LOGIN OAUTH (existing) ════════════════════════ */

app.get('/auth/google', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state, prompt: 'select_account'
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
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI, grant_type: 'authorization_code'
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
      name: profile.name, email: profile.email, picture: profile.picture, provider: 'google',
      approved: existing ? existing.approved : false,
      registeredAt: existing ? existing.registeredAt : Date.now()
    });
    req.session.user = { role: 'student', ...publicUser(user) };
    if (isNew) {
      sendEmail({ to: user.email, subject: 'EduMitra — We received your registration', html: welcomeEmailHtml(user.name) });
      if (SUPERADMIN_EMAIL) sendEmail({ to: SUPERADMIN_EMAIL, subject: `New student signup: ${user.name} (${user.email})`, html: adminNewSignupEmailHtml(user.name, user.email) });
    }
    res.redirect(`${FRONTEND_URL}/?auth=success`);
  } catch (err) {
    console.error('Google OAuth error:', err);
    res.redirect(`${FRONTEND_URL}/?auth=error&reason=google_failed`);
  }
});

/* ════════════════════════ LINKEDIN OAUTH (existing) ════════════════════════ */

app.get('/auth/linkedin', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: process.env.LINKEDIN_CLIENT_ID, redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
    response_type: 'code', scope: 'openid profile email', state
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
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code,
        client_id: process.env.LINKEDIN_CLIENT_ID, client_secret: process.env.LINKEDIN_CLIENT_SECRET,
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
      name: profile.name, email: profile.email, picture: profile.picture, provider: 'linkedin',
      approved: existing ? existing.approved : false,
      registeredAt: existing ? existing.registeredAt : Date.now()
    });
    req.session.user = { role: 'student', ...publicUser(user) };
    if (isNew) {
      sendEmail({ to: user.email, subject: 'EduMitra — We received your registration', html: welcomeEmailHtml(user.name) });
      if (SUPERADMIN_EMAIL) sendEmail({ to: SUPERADMIN_EMAIL, subject: `New student signup: ${user.name} (${user.email})`, html: adminNewSignupEmailHtml(user.name, user.email) });
    }
    res.redirect(`${FRONTEND_URL}/?auth=success`);
  } catch (err) {
    console.error('LinkedIn OAuth error:', err);
    res.redirect(`${FRONTEND_URL}/?auth=error&reason=linkedin_failed`);
  }
});

/* ════════════════════════ STUDENT AUTH (existing) ════════════════════════ */

app.post('/api/auth/signup', signupLimiter, (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid name and email.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const key = email.toLowerCase();
  if (readUsers()[key]) return res.status(409).json({ error: 'An account already exists for this email. Please sign in instead.' });
  const referredBy = (req.body.referredBy || '').toUpperCase().trim() || null;
  const user = upsertUser({
    name, email, passwordHash: hashPassword(password),
    provider: 'password', approved: false, registeredAt: Date.now(),
    referredBy
  });
  req.session.user = { role: 'student', ...publicUser(user) };
  sendEmail({ to: user.email, subject: 'EduMitra — We received your registration', html: welcomeEmailHtml(user.name) });
  if (SUPERADMIN_EMAIL) {
    sendEmail({ to: SUPERADMIN_EMAIL, subject: `New student signup: ${user.name} (${user.email})`, html: adminNewSignupEmailHtml(user.name, user.email) });
  }
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

// Single unified login — detects role (superadmin → admin → counsellor →
// student, in that fixed order) by email, so the homepage doesn't need to
// know in advance which kind of account is signing in. If the same email
// happens to exist in more than one store, the first match in this order
// wins silently — by design (see conversation), not a bug.
app.post('/api/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const key = (email || '').toLowerCase();
  const GENERIC = 'Invalid email or password.';
  if (!key || !password) return res.status(401).json({ error: GENERIC });

  if (SUPERADMIN_EMAIL && key === SUPERADMIN_EMAIL) {
    if (password === SUPERADMIN_PASSWORD) {
      req.session.user = { role: 'superadmin', email: key, name: 'Super Admin' };
      return res.json({ ok: true, user: req.session.user });
    }
    return res.status(401).json({ error: GENERIC });
  }

  const admin = readAdmins()[key];
  if (admin) {
    if (!verifyPassword(password, admin.passwordHash)) return res.status(401).json({ error: GENERIC });
    req.session.user = { role: 'admin', email: key, name: admin.name };
    return res.json({ ok: true, user: req.session.user });
  }

  const counsellor = readCounsellors()[key];
  if (counsellor) {
    if (!verifyPassword(password, counsellor.passwordHash)) return res.status(401).json({ error: GENERIC });
    req.session.user = { role: 'counsellor', email: key, name: counsellor.name };
    return res.json({ ok: true, user: req.session.user });
  }

  const user = readUsers()[key];
  if (user && user.passwordHash) {
    if (!verifyPassword(password, user.passwordHash)) return res.status(401).json({ error: GENERIC });
    req.session.user = { role: 'student', ...publicUser(user) };
    return res.json({ ok: true, user: req.session.user });
  }

  return res.status(401).json({ error: GENERIC });
});

app.post('/api/auth/verify', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') return res.status(401).json({ error: 'Please sign in first.' });
  const verifyData = { ...req.body, submittedAt: Date.now(), verificationStatus: 'pending' };
  const user = upsertUser({ email: req.session.user.email, verifyData });
  req.session.user = { role: 'student', ...publicUser(user) };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/auth/forgot-password', loginLimiter, async (req, res) => {
  const { email } = req.body || {};
  const key = (email || '').toLowerCase();
  // Always respond the same way whether or not the account exists, so this
  // endpoint can't be used to check which emails are registered.
  const GENERIC_OK = { ok: true, message: 'If an account exists for that email, a reset link has been sent.' };
  if (!key || !/\S+@\S+\.\S+/.test(key)) return res.json(GENERIC_OK);

  const account = findAccountByEmail(key);
  if (!account) return res.json(GENERIC_OK);

  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const tokens = readResetTokens();
  // Clear out any old tokens for this email before issuing a new one.
  for (const t of Object.keys(tokens)) {
    if (tokens[t].email === key) delete tokens[t];
  }
  tokens[tokenHash] = {
    email: key,
    role: account.role,
    expires: Date.now() + 60 * 60 * 1000 // 1 hour
  };
  writeResetTokens(tokens);

  const resetUrl = `${FRONTEND_URL}/reset-password.html?token=${rawToken}`;
  const record = account.read()[key];
  sendEmail({
    to: key,
    subject: 'Reset your EduMitra password',
    html: resetPasswordEmailHtml(record.name, resetUrl)
  });

  res.json(GENERIC_OK);
});

app.post('/api/auth/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Invalid or missing reset token.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const tokens = readResetTokens();
  const entry = tokens[tokenHash];
  if (!entry) return res.status(400).json({ error: 'This reset link is invalid. Please request a new one.' });
  if (entry.expires < Date.now()) {
    delete tokens[tokenHash];
    writeResetTokens(tokens);
    return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' });
  }

  const store = account_store_for(entry.role);
  const records = store.read();
  if (!records[entry.email]) return res.status(400).json({ error: 'Account no longer exists.' });
  records[entry.email].passwordHash = hashPassword(password);
  records[entry.email].passwordChangedAt = Date.now();
  store.write(records);

  delete tokens[tokenHash];
  writeResetTokens(tokens);

  res.json({ ok: true });
});

function account_store_for(role) {
  if (role === 'admin') return { read: readAdmins, write: writeAdmins };
  if (role === 'counsellor') return { read: readCounsellors, write: writeCounsellors };
  return { read: readUsers, write: writeUsers };
}

app.get('/api/me', (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, user: req.session.user });
  res.json({ loggedIn: false });
});

app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/auth/logout', (req, res) => { req.session.destroy(() => res.redirect(`${FRONTEND_URL}/`)); });

/* ════════════════════════ PAYMENTS (Razorpay) ════════════════════════ */

const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID     || '',
  key_secret: process.env.RAZORPAY_KEY_SECRET || ''
});

// Price calculation: base + 3% platform fee + 18% GST on total
function calcTotal(basePrice) {
  const base    = parseFloat(basePrice);
  const withFee = base * 1.03;           // +3% platform fee
  const withGST = withFee * 1.18;        // +18% GST on (base + fee)
  return Math.round(withGST * 100) / 100; // round to 2 decimal places
}

// Counsellor: set/update their session fee (sets status to pending approval)
app.post('/api/counsellor/fee', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'counsellor')
    return res.status(401).json({ error: 'Unauthorised.' });
  const { fee } = req.body || {};
  const parsed = parseFloat(fee);
  if (!parsed || parsed <= 0 || parsed > 100000)
    return res.status(400).json({ error: 'Invalid fee amount.' });
  const counsellors = readCounsellors();
  const key = req.session.user.email.toLowerCase();
  if (!counsellors[key]) return res.status(404).json({ error: 'Counsellor not found.' });
  counsellors[key].sessionFee       = parsed;
  counsellors[key].feeStatus        = 'pending';
  counsellors[key].feeSubmittedAt   = Date.now();
  writeCounsellors(counsellors);
  res.json({ ok: true, fee: parsed, feeStatus: 'pending' });
});

// Counsellor: get their own fee info
app.get('/api/counsellor/fee', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'counsellor')
    return res.status(401).json({ error: 'Unauthorised.' });
  const key = req.session.user.email.toLowerCase();
  const c = readCounsellors()[key];
  if (!c) return res.status(404).json({ error: 'Not found.' });
  res.json({ fee: c.sessionFee || null, feeStatus: c.feeStatus || null });
});

// Admin: list counsellors with pending fee approvals
app.get('/api/admin/fee-approvals', (req, res) => {
  if (!req.session.user || !['admin','superadmin'].includes(req.session.user.role))
    return res.status(401).json({ error: 'Unauthorised.' });
  const counsellors = readCounsellors();
  const pending = Object.entries(counsellors)
    .filter(([, c]) => c.feeStatus === 'pending')
    .map(([email, c]) => ({
      email,
      name:          c.name,
      sessionFee:    c.sessionFee,
      feeSubmittedAt: c.feeSubmittedAt
    }));
  res.json({ pending });
});

// Admin: approve or reject a counsellor's fee
app.post('/api/admin/counsellors/:email/fee', (req, res) => {
  if (!req.session.user || !['admin','superadmin'].includes(req.session.user.role))
    return res.status(401).json({ error: 'Unauthorised.' });
  const { action } = req.body || {};   // 'approve' or 'reject'
  if (!['approve','reject'].includes(action))
    return res.status(400).json({ error: 'action must be approve or reject.' });
  const counsellors = readCounsellors();
  const key = decodeURIComponent(req.params.email).toLowerCase();
  if (!counsellors[key]) return res.status(404).json({ error: 'Counsellor not found.' });
  counsellors[key].feeStatus = action === 'approve' ? 'approved' : 'rejected';
  counsellors[key].feeReviewedAt = Date.now();
  writeCounsellors(counsellors);
  res.json({ ok: true, feeStatus: counsellors[key].feeStatus });
});

// Students: list all counsellors with an approved fee
app.get('/api/students/counsellors', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student')
    return res.status(401).json({ error: 'Unauthorised.' });
  const counsellors = readCounsellors();
  const list = Object.entries(counsellors)
    .filter(([, c]) => c.feeStatus === 'approved' && c.sessionFee)
    .map(([email, c]) => ({
      email,
      name:       c.name,
      sessionFee: c.sessionFee,
      total:      calcTotal(c.sessionFee)
    }));
  res.json({ counsellors: list });
});

// Create Razorpay order — called just before showing the payment modal to the student
app.post('/api/payment/create-order', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student')
    return res.status(401).json({ error: 'Unauthorised.' });
  const { counsellorEmail } = req.body || {};
  const c = readCounsellors()[(counsellorEmail || '').toLowerCase()];
  if (!c || c.feeStatus !== 'approved' || !c.sessionFee)
    return res.status(400).json({ error: 'Counsellor fee not available.' });

  const totalRupees = calcTotal(c.sessionFee);
  const amountPaise = Math.round(totalRupees * 100);   // Razorpay uses smallest currency unit

  try {
    const order = await razorpay.orders.create({
      amount:   amountPaise,
      currency: 'INR',
      receipt:  `rcpt_${Date.now()}`,
      notes:    {
        studentEmail:    req.session.user.email,
        counsellorEmail: counsellorEmail,
        baseFee:         c.sessionFee,
        platformFee:     Math.round(c.sessionFee * 0.03 * 100) / 100,
        gst:             Math.round((c.sessionFee * 1.03 * 0.18) * 100) / 100,
        totalAmount:     totalRupees
      }
    });
    res.json({
      ok: true,
      orderId:         order.id,
      amount:          amountPaise,
      amountDisplay:   totalRupees,
      currency:        'INR',
      counsellorName:  c.name,
      counsellorEmail: counsellorEmail,
      keyId:           process.env.RAZORPAY_KEY_ID
    });
  } catch (e) {
    console.error('[razorpay] create-order error:', e.message);
    res.status(500).json({ error: 'Could not create payment order. Please try again.' });
  }
});

// Verify payment signature after Razorpay checkout completes
app.post('/api/payment/verify', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student')
    return res.status(401).json({ error: 'Unauthorised.' });
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
    return res.status(400).json({ error: 'Missing payment details.' });

  const expectedSig = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || '')
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (expectedSig !== razorpay_signature)
    return res.status(400).json({ error: 'Payment verification failed.' });

  // Signature verified — payment is genuine
  res.json({ ok: true, paymentId: razorpay_payment_id });
});

/* ════════════════════════ ADMIN (existing) ════════════════════════ */

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
  const list = Object.values(readUsers()).map(publicUser);
  res.json({ students: list });
});

app.post('/api/admin/students/:email/approve', requireAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const users = readUsers();
  if (!users[key]) return res.status(404).json({ error: 'Student not found.' });
  const wasAlreadyApproved = users[key].approved === true;
  const verifyData = { ...(users[key].verifyData || {}), verificationStatus: 'approved' };
  const assignedCounsellorEmail = (req.body?.assignedCounsellorEmail || '').toLowerCase() || null;
  const updated = upsertUser({
    email: key, approved: true, verifyData,
    adminNote: req.body?.note || '',
    assignedCounsellorEmail,
    approvedAt: new Date().toISOString()
  });
  if (!wasAlreadyApproved) {
    sendEmail({
      to: updated.email, subject: 'Your EduMitra account is approved',
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
    const d = new Date(); d.setDate(d.getDate() - i);
    days.push({ date: d.toISOString().slice(0, 10), count: 0 });
  }
  users.forEach(u => {
    if (!u.registeredAt) return;
    const day = new Date(u.registeredAt).toISOString().slice(0, 10);
    const bucket = days.find(d => d.date === day);
    if (bucket) bucket.count++;
  });
  const recent = users.filter(u => u.registeredAt).sort((a, b) => b.registeredAt - a.registeredAt).slice(0, 8).map(publicUser);
  res.json({ total: users.length, pending, approved, rejected, signupsByDay: days, recent });
});

/* ════════════════════════ SUPER ADMIN — admins ════════════════════════ */

app.get('/api/superadmin/admins', requireSuperAdmin, (req, res) => {
  const admins = Object.values(readAdmins()).map(({ passwordHash, ...safe }) => safe);
  res.json({ admins, superAdminEmail: SUPERADMIN_EMAIL });
});

app.post('/api/superadmin/admins', requireSuperAdmin, (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid name and email.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const key = email.toLowerCase();
  if (key === SUPERADMIN_EMAIL) return res.status(409).json({ error: 'That email is reserved.' });
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

/* ════════════════════════ SUPER ADMIN — counsellors ════════════════════════ */

app.get('/api/superadmin/counsellors', requireSuperAdmin, (req, res) => {
  const list = Object.values(readCounsellors()).map(({ passwordHash, google, ...safe }) => ({
    ...safe,
    calendarConnected: !!(google && google.refreshToken)
  }));
  res.json({ counsellors: list });
});

app.post('/api/superadmin/counsellors', requireSuperAdmin, async (req, res) => {
  const { name, email } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: "Please enter the counsellor's name." });
  if (!email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid email.' });
  const key = email.toLowerCase();
  const counsellors = readCounsellors();
  if (counsellors[key]) return res.status(409).json({ error: 'A counsellor with this email already exists.' });
  if (key === SUPERADMIN_EMAIL) return res.status(409).json({ error: 'That email is reserved.' });
  if (readAdmins()[key]) return res.status(409).json({ error: 'That email is already used by an admin account.' });
  const tempPassword = generatePassword();
  counsellors[key] = {
    name: name.trim(), email: key, passwordHash: hashPassword(tempPassword),
    createdAt: Date.now(), createdBy: req.session.user.email
  };
  writeCounsellors(counsellors);
  const loginUrl = `${FRONTEND_URL}/counsellor-login.html`;
  try {
    await sendEmail({
      to: key, subject: 'Welcome to EduMitra — your counsellor account is ready',
      html: counsellorWelcomeEmailHtml(name.trim(), key, tempPassword, loginUrl)
    });
    res.json({ ok: true, emailed: true });
  } catch (err) {
    console.error('[counsellor create] email failed:', err.message);
    res.json({ ok: true, emailed: false, tempPassword,
      note: 'Account created but the welcome email could not be sent. Share these credentials manually.' });
  }
});

app.delete('/api/superadmin/counsellors/:email', requireSuperAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const counsellors = readCounsellors();
  if (!counsellors[key]) return res.status(404).json({ error: 'Counsellor not found.' });
  delete counsellors[key];
  writeCounsellors(counsellors);
  // Cascade delete the counsellor's slots
  const slots = readSlots();
  Object.keys(slots).forEach(id => { if (slots[id].counsellorEmail === key) delete slots[id]; });
  writeSlots(slots);
  res.json({ ok: true });
});

/* ════════════════════════ COUNSELLOR AUTH + PASSWORD CHANGE ════════════════════════ */

app.post('/api/counsellor/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const key = (email || '').toLowerCase();
  const GENERIC = 'Invalid email or password.';
  const counsellor = readCounsellors()[key];
  if (!counsellor) return res.status(401).json({ error: GENERIC });
  if (!verifyPassword(password || '', counsellor.passwordHash)) return res.status(401).json({ error: GENERIC });
  req.session.user = { role: 'counsellor', email: key, name: counsellor.name };
  res.json({ ok: true, user: req.session.user });
});

app.get('/api/counsellor/me', (req, res) => {
  if (req.session.user && req.session.user.role === 'counsellor') {
    return res.json({ loggedIn: true, user: req.session.user });
  }
  res.json({ loggedIn: false });
});

app.post('/api/counsellor/change-password', requireCounsellor, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword) return res.status(400).json({ error: 'Please enter your current password.' });
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  if (newPassword === currentPassword) return res.status(400).json({ error: 'New password must be different from your current password.' });
  const key = req.session.user.email;
  const counsellors = readCounsellors();
  const counsellor = counsellors[key];
  if (!counsellor) return res.status(404).json({ error: 'Counsellor not found.' });
  if (!verifyPassword(currentPassword, counsellor.passwordHash)) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }
  counsellor.passwordHash = hashPassword(newPassword);
  counsellor.passwordChangedAt = Date.now();
  writeCounsellors(counsellors);
  res.json({ ok: true });
});

/* ════════════════════════ GOOGLE CALENDAR OAUTH (counsellor connects) ════════════════════════ */

function getOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_CALENDAR_REDIRECT_URI || `${FRONTEND_URL}/auth/google/calendar/callback`
  );
}

async function getCalendarForCounsellor(counsellorEmail) {
  const counsellors = readCounsellors();
  const c = counsellors[counsellorEmail.toLowerCase()];
  if (!c || !c.google || !c.google.refreshToken) {
    throw new Error('Counsellor has not connected Google Calendar.');
  }
  const oauth2 = getOAuth2Client();
  oauth2.setCredentials({
    refresh_token: c.google.refreshToken,
    access_token: c.google.accessToken,
    expiry_date: c.google.expiry
  });
  oauth2.on('tokens', (tokens) => {
    try {
      const fresh = readCounsellors();
      const ke = counsellorEmail.toLowerCase();
      if (!fresh[ke]) return;
      fresh[ke].google = {
        ...fresh[ke].google,
        accessToken: tokens.access_token || fresh[ke].google.accessToken,
        expiry: tokens.expiry_date || fresh[ke].google.expiry,
        refreshToken: tokens.refresh_token || fresh[ke].google.refreshToken
      };
      writeCounsellors(fresh);
    } catch (e) {}
  });
  return google.calendar({ version: 'v3', auth: oauth2 });
}

app.get('/auth/google/calendar', requireCounsellor, (req, res) => {
  const oauth2 = getOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/calendar.events',
      'https://www.googleapis.com/auth/calendar.readonly'
    ],
    state: req.session.user.email
  });
  res.redirect(url);
});

app.get('/auth/google/calendar/callback', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'counsellor') {
      return res.redirect(`${FRONTEND_URL}/counsellor-login.html?cal_error=auth`);
    }
    const { code, state } = req.query;
    if (!code) return res.redirect(`${FRONTEND_URL}/counsellor.html?cal_error=no_code`);
    if (state !== req.session.user.email) return res.redirect(`${FRONTEND_URL}/counsellor.html?cal_error=state`);

    const oauth2 = getOAuth2Client();
    const { tokens } = await oauth2.getToken(code);
    const counsellors = readCounsellors();
    const key = req.session.user.email;
    if (!counsellors[key]) return res.redirect(`${FRONTEND_URL}/counsellor.html?cal_error=no_counsellor`);
    counsellors[key].google = {
      refreshToken: tokens.refresh_token || counsellors[key].google?.refreshToken,
      accessToken:  tokens.access_token,
      expiry:       tokens.expiry_date,
      tokenType:    tokens.token_type,
      scope:        tokens.scope,
      connectedAt:  Date.now()
    };
    writeCounsellors(counsellors);
    res.redirect(`${FRONTEND_URL}/counsellor.html?cal_success=1`);
  } catch (err) {
    console.error('Calendar OAuth callback error:', err);
    res.redirect(`${FRONTEND_URL}/counsellor.html?cal_error=token`);
  }
});

app.post('/api/counsellor/calendar/disconnect', requireCounsellor, (req, res) => {
  const counsellors = readCounsellors();
  const key = req.session.user.email;
  if (counsellors[key]) {
    delete counsellors[key].google;
    writeCounsellors(counsellors);
  }
  res.json({ ok: true });
});

app.get('/api/counsellor/calendar/status', requireCounsellor, (req, res) => {
  const counsellors = readCounsellors();
  const c = counsellors[req.session.user.email];
  res.json({ connected: !!(c && c.google && c.google.refreshToken) });
});

/* ════════════════════════ SLOTS — counsellor side ════════════════════════ */

app.get('/api/counsellor/slots', requireCounsellor, (req, res) => {
  const key = req.session.user.email;
  const slots = Object.values(readSlots())
    .filter(s => s.counsellorEmail === key)
    .sort((a, b) => (a.date + a.startTime).localeCompare(b.date + b.startTime));
  res.json({ slots });
});

app.post('/api/counsellor/slots', requireCounsellor, (req, res) => {
  const { date, startTime, endTime, label } = req.body || {};
  if (!date || !startTime || !endTime) return res.status(400).json({ error: 'Date, start time and end time are required.' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Date must be in YYYY-MM-DD format.' });
  if (!/^\d{2}:\d{2}$/.test(startTime) || !/^\d{2}:\d{2}$/.test(endTime)) return res.status(400).json({ error: 'Times must be HH:MM.' });
  if (startTime >= endTime) return res.status(400).json({ error: 'End time must be after start time.' });

  const counsellors = readCounsellors();
  const c = counsellors[req.session.user.email];
  if (!c || !c.google || !c.google.refreshToken) {
    return res.status(400).json({ error: 'Please connect your Google Calendar first.' });
  }

  const slots = readSlots();
  const id = Date.now();
  slots[id] = {
    id, counsellorEmail: req.session.user.email,
    date, startTime, endTime, label: (label || '').trim() || 'General Counselling',
    booked: false, bookedBy: null, bookedAt: null,
    googleEventId: null, meetLink: null, createdAt: Date.now()
  };
  writeSlots(slots);
  res.json({ ok: true, slot: slots[id] });
});

app.delete('/api/counsellor/slots/:id', requireCounsellor, async (req, res) => {
  const id = req.params.id;
  const slots = readSlots();
  const slot = slots[id];
  if (!slot) return res.status(404).json({ error: 'Slot not found.' });
  if (slot.counsellorEmail !== req.session.user.email) return res.status(403).json({ error: 'Not your slot.' });
  if (slot.booked && slot.googleEventId) {
    try {
      const cal = await getCalendarForCounsellor(slot.counsellorEmail);
      await cal.events.delete({ calendarId: 'primary', eventId: slot.googleEventId, sendUpdates: 'all' });
    } catch (err) {
      console.warn('Could not delete calendar event:', err.message);
    }
  }
  delete slots[id];
  writeSlots(slots);
  res.json({ ok: true });
});

/* ════════════════════════ SLOTS — student side ════════════════════════ */

// All available future slots from all counsellors
app.get('/api/student/slots', requireStudent, (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const counsellors = readCounsellors();
  const slots = Object.values(readSlots())
    .filter(s => !s.booked && s.date >= today)
    .sort((a, b) => (a.date + a.startTime).localeCompare(b.date + b.startTime))
    .map(s => ({ ...s, counsellorName: counsellors[s.counsellorEmail]?.name || 'Counsellor' }));
  res.json({ slots });
});

// Student's booked sessions
app.get('/api/student/bookings', requireStudent, (req, res) => {
  const counsellors = readCounsellors();
  const list = Object.values(readSlots())
    .filter(s => s.bookedBy === req.session.user.email)
    .sort((a, b) => (b.date + b.startTime).localeCompare(a.date + a.startTime))
    .map(s => ({ ...s, counsellorName: counsellors[s.counsellorEmail]?.name || 'Counsellor' }));
  res.json({ bookings: list });
});

// Book a slot — creates Calendar event with Meet link
app.post('/api/student/book/:slotId', requireStudent, async (req, res) => {
  const id = req.params.slotId;
  const slots = readSlots();
  const slot = slots[id];
  if (!slot) return res.status(404).json({ error: 'Slot not found.' });
  if (slot.booked) return res.status(409).json({ error: 'This slot has already been booked.' });

  const student = readUsers()[req.session.user.email];
  if (!student) return res.status(404).json({ error: 'Student profile not found.' });
  if (!student.approved) return res.status(403).json({ error: 'Your account must be approved before booking sessions.' });

  const counsellor = readCounsellors()[slot.counsellorEmail];
  if (!counsellor) return res.status(404).json({ error: 'Counsellor not found.' });

  try {
    const calendar = await getCalendarForCounsellor(slot.counsellorEmail);
    const startISO = `${slot.date}T${slot.startTime}:00`;
    const endISO   = `${slot.date}T${slot.endTime}:00`;

    const event = await calendar.events.insert({
      calendarId: 'primary',
      conferenceDataVersion: 1,
      sendUpdates: 'all',
      requestBody: {
        summary: `EduMitra Counselling: ${student.name || student.email}`,
        description: `Counselling session booked via EduMitra.\n\nCounsellor: ${counsellor.name}\nStudent: ${student.name || student.email}\nTopic: ${slot.label || 'General Counselling'}`,
        start: { dateTime: startISO, timeZone: 'Asia/Kolkata' },
        end:   { dateTime: endISO,   timeZone: 'Asia/Kolkata' },
        attendees: [{ email: student.email }, { email: slot.counsellorEmail }],
        conferenceData: {
          createRequest: {
            requestId: `edumitra-${slot.id}-${Date.now()}`,
            conferenceSolutionKey: { type: 'hangoutsMeet' }
          }
        }
      }
    });

    const meetLink = event.data.hangoutLink
      || event.data.conferenceData?.entryPoints?.find(e => e.entryPointType === 'video')?.uri
      || null;

    slot.booked = true;
    slot.bookedBy = student.email;
    slot.bookedAt = Date.now();
    slot.googleEventId = event.data.id;
    slot.meetLink = meetLink;
    writeSlots(slots);

    const emailHtml = bookingEmailHtml({
      studentName: student.name || student.email,
      counsellorName: counsellor.name,
      date: slot.date, startTime: slot.startTime, endTime: slot.endTime,
      label: slot.label, meetLink
    });
    sendEmail({ to: student.email,        subject: 'Your EduMitra session is booked', html: emailHtml });
    sendEmail({ to: slot.counsellorEmail, subject: `New session booked by ${student.name || student.email}`, html: emailHtml });

    res.json({ ok: true, meetLink, slot });
  } catch (err) {
    console.error('Booking error:', err);
    res.status(500).json({ error: 'Could not create Google Meet event: ' + (err.message || 'unknown error') });
  }
});


/* ════════════════════════ COUNSELLOR — assigned students ════════════════════════ */

// Returns all approved students assigned to the currently logged-in counsellor
app.get('/api/counsellor/students', requireCounsellor, (req, res) => {
  const key = req.session.user.email;
  const students = Object.values(readUsers())
    .filter(u => u.role === 'student' && u.approved && u.assignedCounsellorEmail === key)
    .map(publicUser)
    .sort((a, b) => (b.approvedAt || 0) > (a.approvedAt || 0) ? 1 : -1);
  res.json({ students });
});

/* ════════════════════════ COUNSELLOR — schedule meet ════════════════════════ */

// Creates a Google Calendar event with Meet link and emails the student
app.post('/api/counsellor/schedule-meet', requireCounsellor, async (req, res) => {
  const { studentEmail, date, time, duration, sessionNum, sessionType, agenda } = req.body || {};
  if (!studentEmail || !date || !time) {
    return res.status(400).json({ error: 'studentEmail, date, and time are required.' });
  }

  const counsellorEmail = req.session.user.email;
  const counsellors = readCounsellors();
  const counsellor = counsellors[counsellorEmail];
  if (!counsellor) return res.status(404).json({ error: 'Counsellor not found.' });

  const student = readUsers()[studentEmail.toLowerCase()];
  if (!student) return res.status(404).json({ error: 'Student not found.' });

  // Check Google Calendar is connected
  if (!counsellor.google || !counsellor.google.refreshToken) {
    return res.status(400).json({ error: 'Please connect your Google Calendar first before scheduling sessions.' });
  }

  try {
    const durationMins = parseInt(duration || 60, 10);
    const startISO = `${date}T${time}:00`;
    const endDate = new Date(`${date}T${time}:00`);
    endDate.setMinutes(endDate.getMinutes() + durationMins);
    const endISO = endDate.toISOString().slice(0, 19);

    const calendar = await getCalendarForCounsellor(counsellorEmail);
    const event = await calendar.events.insert({
      calendarId: 'primary',
      conferenceDataVersion: 1,
      sendUpdates: 'all',
      requestBody: {
        summary: `EduMitra Session #${sessionNum || '?'}: ${student.name || student.email}`,
        description: `EduMitra counselling session.\n\nCounsellor: ${counsellor.name}\nStudent: ${student.name || student.email}\nType: ${sessionType || 'General Counselling'}\n\n${agenda ? 'Agenda:\n' + agenda : ''}`,
        start: { dateTime: startISO, timeZone: 'Asia/Kolkata' },
        end:   { dateTime: endISO,   timeZone: 'Asia/Kolkata' },
        attendees: [
          { email: student.email },
          { email: counsellorEmail }
        ],
        conferenceData: {
          createRequest: {
            requestId: `edumitra-${Date.now()}`,
            conferenceSolutionKey: { type: 'hangoutsMeet' }
          }
        }
      }
    });

    const meetLink = event.data.hangoutLink
      || event.data.conferenceData?.entryPoints?.find(e => e.entryPointType === 'video')?.uri
      || null;

    // Send email to student
    if (meetLink) {
      const dateObj = new Date(`${date}T${time}:00`);
      const dateStr = dateObj.toLocaleDateString('en-IN', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
      const timeStr = dateObj.toLocaleTimeString('en-IN', { hour:'2-digit', minute:'2-digit', hour12:true });

      const emailHtml = `<!DOCTYPE html>
<html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;">
    <h2 style="color:#0a1628;margin:0 0 12px;">Your EduMitra Session is Confirmed</h2>
    <p style="line-height:1.6;font-size:14.5px;">Hi ${student.name || 'there'},</p>
    <p style="line-height:1.6;font-size:14.5px;">Your counselling session with <strong>${counsellor.name}</strong> has been scheduled.</p>
    <div style="background:#f0f9ff;border-radius:10px;padding:18px 20px;margin:20px 0;">
      <p style="margin:0 0 8px;font-size:14px;">📅 <strong>${dateStr} at ${timeStr}</strong> (${durationMins} min)</p>
      <p style="margin:0 0 8px;font-size:14px;">📋 <strong>Session #${sessionNum || '?'}</strong> — ${sessionType || 'General Counselling'}</p>
      ${agenda ? `<p style="margin:0;font-size:14px;">📝 <strong>Agenda:</strong> ${agenda}</p>` : ''}
    </div>
    <p style="text-align:center;margin:24px 0;">
      <a href="${meetLink}" style="display:inline-block;padding:13px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;font-size:14px;">🎥 Join Google Meet</a>
    </p>
    <p style="font-size:13px;color:#6b7280;">Or copy this link: ${meetLink}</p>
    <p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p>
  </div>
</body></html>`;

      sendEmail({ to: student.email, subject: `Your EduMitra session is confirmed — ${dateStr}`, html: emailHtml });
      sendEmail({ to: counsellorEmail, subject: `Session confirmed with ${student.name || student.email}`, html: emailHtml });
    }

    res.json({ ok: true, meetLink, eventId: event.data.id });

  } catch (err) {
    console.error('[schedule-meet] error:', err);
    res.status(500).json({ error: 'Could not create Google Meet event: ' + (err.message || 'unknown error') });
  }
});


/* ════════════════════════ REFERRALS ════════════════════════ */

// Generate deterministic referral code from email (matches client-side logic)
function getReferralCode(email) {
  const local = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 4);
  let hash = 0;
  for (let i = 0; i < email.length; i++) hash = (hash * 31 + email.charCodeAt(i)) & 0xffff;
  return 'EDU' + local + String(hash).slice(-3).padStart(3, '0');
}

// Get student's referral history and earnings
app.get('/api/student/referrals', requireStudent, (req, res) => {
  const email = req.session.user.email;
  const refCode = getReferralCode(email);
  const users = readUsers();
  
  // Find all users who were referred by this student's code
  const referred = Object.values(users).filter(u => u.referredBy === refCode);
  const referrals = referred.map(u => {
    const firstBooking = Object.values(readSlots()).find(s => s.bookedBy === u.email);
    return {
      name: u.name || u.email,
      email: u.email,
      referredAt: u.registeredAt,
      status: firstBooking ? 'completed' : (u.approved ? 'signed_up' : 'pending')
    };
  });

  const totalEarned = referrals.filter(r => r.status === 'completed').length * 500;
  res.json({ referralCode: refCode, referrals, totalEarned });
});

// Apply referral code at signup (called during signup with referredBy field)
// The signup endpoint already exists — we just need to store the referredBy field
// when a student signs up. This endpoint validates a code before signup.
app.get('/api/referral/validate/:code', (req, res) => {
  const code = (req.params.code || '').toUpperCase().trim();
  if (!code) return res.status(400).json({ error: 'No code provided.' });
  
  // Find which user owns this code
  const users = readUsers();
  const owner = Object.values(users).find(u => getReferralCode(u.email) === code);
  if (!owner) return res.status(404).json({ valid: false, error: 'Invalid referral code.' });
  
  // Can't refer yourself
  if (req.session.user && req.session.user.email === owner.email) {
    return res.status(400).json({ valid: false, error: 'You cannot use your own referral code.' });
  }
  
  res.json({ valid: true, discount: 250, ownerName: owner.name || 'an EduMitra user' });
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
