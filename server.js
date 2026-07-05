require('dotenv').config();
// Polyfill WebSocket for Supabase on Node < 18
if (!globalThis.WebSocket) { globalThis.WebSocket = require('ws'); }
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
const cookieParse = require('cookie').parse;
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { google } = require('googleapis');
const { createClient: createSupabaseClient } = require('@supabase/supabase-js');

const supabase = createSupabaseClient(
  process.env.SUPABASE_URL || '',
  process.env.SUPABASE_SERVICE_KEY || ''
);

const app = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL = process.env.FRONTEND_URL || `http://localhost:${PORT}`;
const SUPERADMIN_EMAIL    = (process.env.SUPERADMIN_EMAIL || '').toLowerCase();
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || '';

app.set('trust proxy', 1);
app.use(express.json());

// Prevent CDN and browser caching on all API routes
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

/* ── Supabase Session Store ── */
const Store = session.Store;
class SupabaseStore extends Store {
  constructor() { super(); this._clean(); }
  async _clean() {
    try { await supabase.from('sessions').delete().lt('expire', new Date().toISOString()); } catch(e) {}
    setTimeout(() => this._clean(), 10 * 60 * 1000); // clean every 10 min
  }
  async get(sid, cb) {
    try {
      const { data } = await supabase.from('sessions').select('sess').eq('sid', sid).gt('expire', new Date().toISOString()).maybeSingle();
      cb(null, data ? data.sess : null);
    } catch(e) { cb(null, null); }
  }
  async set(sid, sess, cb) {
    try {
      const expire = sess.cookie?.expires ? new Date(sess.cookie.expires) : new Date(Date.now() + 7*24*60*60*1000);
      await supabase.from('sessions').upsert({ sid, sess, expire: expire.toISOString() }, { onConflict: 'sid' });
      cb(null);
    } catch(e) { cb(null); }
  }
  async destroy(sid, cb) {
    try { await supabase.from('sessions').delete().eq('sid', sid); } catch(e) {}
    if (cb) cb(null);
  }
}

console.log('[session] Using Supabase session store');

app.use(session({
  store: new SupabaseStore(),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000, secure: false }
}));
app.use(express.static(path.join(__dirname, 'public')));

const pages = ['dashboard','admin','counsellor','counsellor-login','pending','reset-password','login'];
pages.forEach(p => { app.get('/' + p, (req, res) => res.sendFile(path.join(__dirname, 'public', p + '.html'))); });

/* ════════════════════════ RATE LIMITERS ════════════════════════ */
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Please try again in 15 minutes.' } });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many signup attempts. Please try again later.' } });

/* ════════════════════════ ZEPTO MAIL ════════════════════════ */
const mailer = nodemailer.createTransport({ host: process.env.ZEPTO_HOST || 'smtp.zeptomail.in', port: parseInt(process.env.ZEPTO_PORT || '587', 10), secure: false, auth: { user: process.env.ZEPTO_USER, pass: process.env.ZEPTO_PASS } });
if (process.env.ZEPTO_USER && process.env.ZEPTO_PASS) {
  mailer.verify().then(() => console.log('[mail] Zepto Mail SMTP ready'), err => console.warn('[mail] Zepto Mail not reachable:', err.message));
} else { console.warn('[mail] ZEPTO_USER / ZEPTO_PASS not set'); }
async function sendEmail({ to, subject, html }) {
  if (!process.env.ZEPTO_USER) { console.warn('[mail] skipping email to', to); return; }
  try { await mailer.sendMail({ from: process.env.ZEPTO_FROM || 'info@edumitra.co', to, subject, html }); console.log('[mail] sent to', to); }
  catch (err) { console.error('[mail] failed to', to, '·', err.message); }
}

/* ════════════════════════ SUPABASE DATA LAYER ════════════════════════ */

function rowToUser(row) {
  if (!row) return null;
  return { email: row.email, name: row.name, picture: row.picture, provider: row.provider, passwordHash: row.password_hash, approved: row.approved, registeredAt: row.registered_at, updatedAt: row.updated_at, referredBy: row.referred_by, verifyData: row.verify_data || {}, adminNote: row.admin_note || '', assignedCounsellorEmail: row.assigned_counsellor_email, approvedAt: row.approved_at };
}
function rowToCounsellor(row) {
  if (!row) return null;
  return { email: row.email, name: row.name, passwordHash: row.password_hash, createdAt: row.created_at, createdBy: row.created_by, passwordChangedAt: row.password_changed_at, sessionFee: row.session_fee, feeStatus: row.fee_status, feeSubmittedAt: row.fee_submitted_at, feeReviewedAt: row.fee_reviewed_at, google: row.google };
}
function rowToAdmin(row) {
  if (!row) return null;
  return { email: row.email, name: row.name, passwordHash: row.password_hash, createdAt: row.created_at };
}
function rowToSlot(row) {
  if (!row) return null;
  return { id: row.id, counsellorEmail: row.counsellor_email, date: row.date, startTime: row.start_time, endTime: row.end_time, label: row.label, booked: row.booked, bookedBy: row.booked_by, meetLink: row.meet_link, googleEventId: row.google_event_id, createdAt: row.created_at };
}

async function getUser(email) {
  const { data } = await supabase.from('users').select('*').eq('email', email.toLowerCase()).maybeSingle();
  return rowToUser(data);
}
async function getAllUsers() {
  const { data } = await supabase.from('users').select('*');
  const result = {}; (data || []).forEach(row => { result[row.email] = rowToUser(row); }); return result;
}
async function saveUser(userObj) {
  const email = userObj.email.toLowerCase();
  const row = { email, name: userObj.name, picture: userObj.picture || null, provider: userObj.provider || 'password', password_hash: userObj.passwordHash || null, approved: userObj.approved !== undefined ? userObj.approved : false, registered_at: userObj.registeredAt || Date.now(), updated_at: new Date().toISOString(), referred_by: userObj.referredBy || null, verify_data: userObj.verifyData || {}, admin_note: userObj.adminNote || '', assigned_counsellor_email: userObj.assignedCounsellorEmail || null, approved_at: userObj.approvedAt || null };
  const { data, error } = await supabase.from('users').upsert(row, { onConflict: 'email' }).select().single();
  if (error) throw error;
  return rowToUser(data);
}
async function upsertUserDB(profile) {
  const existing = await getUser(profile.email);
  const merged = { ...(existing || {}), ...profile, email: profile.email.toLowerCase(), updatedAt: new Date().toISOString() };
  return saveUser(merged);
}

async function getCounsellor(email) {
  const { data } = await supabase.from('counsellors').select('*').eq('email', email.toLowerCase()).maybeSingle();
  return rowToCounsellor(data);
}
async function getAllCounsellors() {
  const { data } = await supabase.from('counsellors').select('*');
  const result = {}; (data || []).forEach(row => { result[row.email] = rowToCounsellor(row); }); return result;
}
async function saveCounsellor(cObj) {
  const email = cObj.email.toLowerCase();
  const row = { email, name: cObj.name, password_hash: cObj.passwordHash || null, created_at: cObj.createdAt || Date.now(), created_by: cObj.createdBy || null, password_changed_at: cObj.passwordChangedAt || null, session_fee: cObj.sessionFee || null, fee_status: cObj.feeStatus || 'none', fee_submitted_at: cObj.feeSubmittedAt || null, fee_reviewed_at: cObj.feeReviewedAt || null, google: cObj.google || null };
  const { data, error } = await supabase.from('counsellors').upsert(row, { onConflict: 'email' }).select().single();
  if (error) throw error;
  return rowToCounsellor(data);
}
async function deleteCounsellor(email) {
  await supabase.from('counsellors').delete().eq('email', email.toLowerCase());
}

async function getAdmin(email) {
  const { data } = await supabase.from('admins').select('*').eq('email', email.toLowerCase()).maybeSingle();
  return rowToAdmin(data);
}
async function getAllAdmins() {
  const { data } = await supabase.from('admins').select('*');
  const result = {}; (data || []).forEach(row => { result[row.email] = rowToAdmin(row); }); return result;
}
async function saveAdmin(aObj) {
  const email = aObj.email.toLowerCase();
  const row = { email, name: aObj.name, password_hash: aObj.passwordHash || null, created_at: aObj.createdAt || Date.now() };
  const { data, error } = await supabase.from('admins').upsert(row, { onConflict: 'email' }).select().single();
  if (error) throw error;
  return rowToAdmin(data);
}
async function deleteAdmin(email) {
  await supabase.from('admins').delete().eq('email', email.toLowerCase());
}

async function getAllSlots() {
  const { data } = await supabase.from('slots').select('*');
  const result = {}; (data || []).forEach(row => { result[String(row.id)] = rowToSlot(row); }); return result;
}
async function saveSlot(sObj) {
  const row = { id: sObj.id, counsellor_email: sObj.counsellorEmail, date: sObj.date, start_time: sObj.startTime, end_time: sObj.endTime, label: sObj.label, booked: sObj.booked || false, booked_by: sObj.bookedBy || null, meet_link: sObj.meetLink || null, google_event_id: sObj.googleEventId || null, created_at: sObj.createdAt || Date.now() };
  const { error } = await supabase.from('slots').upsert(row, { onConflict: 'id' });
  if (error) throw error;
}
async function deleteSlot(id) {
  await supabase.from('slots').delete().eq('id', id);
}

// Reset tokens — keep file-based (temporary, don't need to persist across deploys)
const RESET_TOKENS_FILE = path.join(__dirname, 'data', 'reset-tokens.json');
function readResetTokens() { try { return JSON.parse(fs.readFileSync(RESET_TOKENS_FILE, 'utf8')); } catch (e) { return {}; } }
function writeResetTokens(t) { fs.mkdirSync(path.dirname(RESET_TOKENS_FILE), { recursive: true }); fs.writeFileSync(RESET_TOKENS_FILE, JSON.stringify(t, null, 2)); }

function publicUser(u) { if (!u) return u; const { passwordHash, ...safe } = u; return safe; }

/* ════════════════════════ PASSWORD HASHING ════════════════════════ */
function hashPassword(password) { const salt = crypto.randomBytes(16).toString('hex'); const hash = crypto.scryptSync(password, salt, 64).toString('hex'); return `${salt}:${hash}`; }
function verifyPassword(password, stored) { if (!stored || !stored.includes(':')) return false; const [salt, hash] = stored.split(':'); const attempt = crypto.scryptSync(password, salt, 64).toString('hex'); try { return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex')); } catch (e) { return false; } }
function generatePassword() { const upper='ABCDEFGHJKMNPQRSTUVWXYZ',lower='abcdefghjkmnpqrstuvwxyz',digit='23456789',symbol='!@#$%&*',all=upper+lower+digit+symbol; let pw=[upper[crypto.randomInt(0,upper.length)],lower[crypto.randomInt(0,lower.length)],digit[crypto.randomInt(0,digit.length)],symbol[crypto.randomInt(0,symbol.length)]]; for(let i=0;i<8;i++)pw.push(all[crypto.randomInt(0,all.length)]); for(let i=pw.length-1;i>0;i--){const j=crypto.randomInt(0,i+1);[pw[i],pw[j]]=[pw[j],pw[i]];} return pw.join(''); }

/* ════════════════════════ ROLE MIDDLEWARE ════════════════════════ */
function requireAdmin(req, res, next) { if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'superadmin')) return next(); res.status(401).json({ error: 'Not authorized.' }); }
function requireSuperAdmin(req, res, next) { if (req.session.user && req.session.user.role === 'superadmin') return next(); res.status(401).json({ error: 'Super admin access only.' }); }
function requireCounsellor(req, res, next) { if (req.session.user && req.session.user.role === 'counsellor') return next(); res.status(401).json({ error: 'Counsellor access only.' }); }
function requireStudent(req, res, next) { if (req.session.user && req.session.user.role === 'student') return next(); res.status(401).json({ error: 'Please sign in first.' }); }

/* ════════════════════════ EMAIL TEMPLATES ════════════════════════ */
function escapeForEmail(str) { return String(str).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function escapeHtml(str) { return String(str||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function escapeAttr(str) { return String(str||'').replace(/['"]/g, c => c==='"'?'&quot;':'&#39;'); }

function welcomeEmailHtml(name) { return `<!DOCTYPE html><html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;"><div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;"><h2 style="color:#0a1628;margin:0 0 12px;">Welcome to EduMitra</h2><p>Hi ${escapeForEmail(name||'there')},</p><p>Thank you for signing up. Your registration has been received and our admin team is currently reviewing it.</p><p>Once approved, you will receive a second email with a direct link to your student dashboard.</p><p style="line-height:1.6;font-size:14.5px;margin-top:24px;">— Team EduMitra</p></div></body></html>`; }
function adminNewSignupEmailHtml(studentName, studentEmail) { return `<!DOCTYPE html><html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;"><div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;"><h2 style="color:#0a1628;margin:0 0 12px;">New student pending approval</h2><p>Name: <strong>${escapeForEmail(studentName||'—')}</strong></p><p>Email: <strong>${escapeForEmail(studentEmail)}</strong></p><p><a href="${FRONTEND_URL}/admin" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;">Review in Admin Panel →</a></p></div></body></html>`; }
function approvalEmailHtml(name, dashboardUrl) { return `<!DOCTYPE html><html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;"><div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;"><h2 style="color:#0a1628;margin:0 0 12px;">Your account is approved</h2><p>Hi ${escapeForEmail(name||'there')},</p><p>Your EduMitra account has been approved. You can now access your student dashboard.</p><p><a href="${dashboardUrl}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;">Go to my dashboard</a></p><p style="margin-top:24px;">— Team EduMitra</p></div></body></html>`; }
function counsellorWelcomeEmailHtml(name, email, password, loginUrl) { return `<!DOCTYPE html><html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;"><div style="max-width:560px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;"><h2 style="color:#0a1628;margin:0 0 12px;">Welcome to EduMitra, ${escapeForEmail(name)}</h2><p>Your counsellor account has been created.</p><div style="background:#faf7f2;border:1px solid #eaedf5;border-radius:10px;padding:20px;margin:22px 0;"><p><strong>Email:</strong> ${escapeForEmail(email)}</p><p><strong>Temporary password:</strong> <code>${escapeForEmail(password)}</code></p></div><p><a href="${loginUrl}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;">Log in to counsellor portal</a></p><p style="margin-top:24px;">— Team EduMitra</p></div></body></html>`; }
function resetPasswordEmailHtml(name, resetUrl) { return `<!DOCTYPE html><html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;"><div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;"><h2 style="color:#0a1628;margin:0 0 12px;">Reset your password</h2><p>Hi ${escapeForEmail(name||'there')},</p><p>Click below to reset your EduMitra password. This link expires in 1 hour.</p><p><a href="${resetUrl}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;">Reset password</a></p><p style="margin-top:24px;">— Team EduMitra</p></div></body></html>`; }
function bookingEmailHtml({ studentName, counsellorName, date, startTime, endTime, label, meetLink }) { const niceDate = new Date(date+'T00:00:00').toLocaleDateString('en-IN',{weekday:'long',day:'numeric',month:'long',year:'numeric'}); return `<!DOCTYPE html><html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;background:#faf7f2;padding:40px 20px;"><div style="max-width:560px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;border:1px solid #eaedf5;"><h2 style="color:#0a1628;margin:0 0 12px;">Your counselling session is booked</h2><p>Hi ${escapeForEmail(studentName)},</p><p>Your slot with <strong>${escapeForEmail(counsellorName)}</strong> is confirmed.</p><div style="background:#faf7f2;border:1px solid #eaedf5;border-radius:10px;padding:20px;margin:22px 0;"><p><strong>Date:</strong> ${niceDate}</p><p><strong>Time:</strong> ${startTime} – ${endTime} (IST)</p><p><strong>Topic:</strong> ${escapeForEmail(label||'General Counselling')}</p></div><p><a href="${meetLink}" style="display:inline-block;padding:12px 28px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;">Join Google Meet</a></p></div></body></html>`; }

/* ════════════════════════ SESSION HELPER ════════════════════════ */
function loginSession(req, userData) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.user = userData;
      req.session.save((err2) => { if (err2) return reject(err2); resolve(); });
    });
  });
}

/* ════════════════════════ GOOGLE OAUTH ════════════════════════ */
app.get('/auth/google', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  res.cookie('oauth_state', state, { httpOnly: true, sameSite: 'lax', maxAge: 5 * 60 * 1000 });
  const params = new URLSearchParams({ client_id: process.env.GOOGLE_CLIENT_ID, redirect_uri: process.env.GOOGLE_REDIRECT_URI, response_type: 'code', scope: 'openid email profile', state, prompt: 'select_account' });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const expectedState = req.session.oauthState || cookieParse(req.headers.cookie||'').oauth_state;
    if (!code || state !== expectedState) return res.redirect(`${FRONTEND_URL}/?auth=error&reason=state_mismatch`);
    res.clearCookie('oauth_state');
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, redirect_uri: process.env.GOOGLE_REDIRECT_URI, grant_type: 'authorization_code' }) });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('No access token from Google');
    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const profile = await profileRes.json();
    const existing = await getUser(profile.email);
    const isNew = !existing;
    const user = await upsertUserDB({ name: profile.name, email: profile.email, picture: profile.picture, provider: 'google', approved: existing ? existing.approved : false, registeredAt: existing ? existing.registeredAt : Date.now() });
    const userData = { role: 'student', ...publicUser(user) };
    if (isNew) {
      sendEmail({ to: user.email, subject: 'EduMitra — We received your registration', html: welcomeEmailHtml(user.name) });
      if (SUPERADMIN_EMAIL) sendEmail({ to: SUPERADMIN_EMAIL, subject: `New student signup: ${user.name} (${user.email})`, html: adminNewSignupEmailHtml(user.name, user.email) });
    }
    await loginSession(req, userData);
    res.redirect(`${FRONTEND_URL}/auth/verify-session`);
  } catch (err) {
    console.error('Google OAuth error:', err);
    res.redirect(`${FRONTEND_URL}/?auth=error&reason=google_failed`);
  }
});

/* ════════════════════════ LINKEDIN OAUTH ════════════════════════ */
app.get('/auth/linkedin', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  res.cookie('oauth_state', state, { httpOnly: true, sameSite: 'lax', maxAge: 5 * 60 * 1000 });
  const params = new URLSearchParams({ client_id: process.env.LINKEDIN_CLIENT_ID, redirect_uri: process.env.LINKEDIN_REDIRECT_URI, response_type: 'code', scope: 'openid profile email', state });
  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params}`);
});

app.get('/auth/linkedin/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const expectedState = req.session.oauthState || cookieParse(req.headers.cookie||'').oauth_state;
    if (!code || state !== expectedState) return res.redirect(`${FRONTEND_URL}/?auth=error&reason=state_mismatch`);
    const tokenRes = await fetch('https://www.linkedin.com/oauth/v2/accessToken', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, client_id: process.env.LINKEDIN_CLIENT_ID, client_secret: process.env.LINKEDIN_CLIENT_SECRET, redirect_uri: process.env.LINKEDIN_REDIRECT_URI }) });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('No access token from LinkedIn');
    const profileRes = await fetch('https://api.linkedin.com/v2/userinfo', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
    const profile = await profileRes.json();
    const existing = await getUser(profile.email);
    const isNew = !existing;
    const user = await upsertUserDB({ name: profile.name, email: profile.email, picture: profile.picture, provider: 'linkedin', approved: existing ? existing.approved : false, registeredAt: existing ? existing.registeredAt : Date.now() });
    const userData = { role: 'student', ...publicUser(user) };
    if (isNew) {
      sendEmail({ to: user.email, subject: 'EduMitra — We received your registration', html: welcomeEmailHtml(user.name) });
      if (SUPERADMIN_EMAIL) sendEmail({ to: SUPERADMIN_EMAIL, subject: `New student signup: ${user.name} (${user.email})`, html: adminNewSignupEmailHtml(user.name, user.email) });
    }
    await loginSession(req, userData);
    res.redirect(`${FRONTEND_URL}/auth/verify-session`);
  } catch (err) {
    console.error('LinkedIn OAuth error:', err);
    res.redirect(`${FRONTEND_URL}/?auth=error&reason=linkedin_failed`);
  }
});

/* ════════════════════════ STUDENT AUTH ════════════════════════ */
app.post('/api/auth/signup', signupLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid name and email.' });
    if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    const key = email.toLowerCase();
    const existing = await getUser(key);
    if (existing) return res.status(409).json({ error: 'An account already exists for this email. Please sign in instead.' });
    const referredBy = (req.body.referredBy || '').toUpperCase().trim() || null;
    const user = await saveUser({ name, email: key, passwordHash: hashPassword(password), provider: 'password', approved: false, registeredAt: Date.now(), referredBy });
    sendEmail({ to: user.email, subject: 'EduMitra — We received your registration', html: welcomeEmailHtml(user.name) });
    if (SUPERADMIN_EMAIL) sendEmail({ to: SUPERADMIN_EMAIL, subject: `New student signup: ${user.name} (${user.email})`, html: adminNewSignupEmailHtml(user.name, user.email) });
    const userData = { role: 'student', ...publicUser(user) };
    await loginSession(req, userData);
    res.json({ ok: true, user: req.session.user });
  } catch (err) { console.error('Signup error:', err); res.status(500).json({ error: 'Signup failed. Please try again.' }); }
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await getUser((email || '').toLowerCase());
    const GENERIC = 'Invalid email or password.';
    if (!user || !user.passwordHash || !verifyPassword(password || '', user.passwordHash)) return res.status(401).json({ error: GENERIC });
    const userData = { role: 'student', ...publicUser(user) };
    await loginSession(req, userData);
    res.json({ ok: true, user: req.session.user });
  } catch (err) { res.status(500).json({ error: 'Login failed.' }); }
});

app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const key = (email || '').toLowerCase();
    const GENERIC = 'Invalid email or password.';
    if (!key || !password) return res.status(401).json({ error: GENERIC });
    let userData = null;
    if (SUPERADMIN_EMAIL && key === SUPERADMIN_EMAIL) {
      if (password !== SUPERADMIN_PASSWORD) return res.status(401).json({ error: GENERIC });
      userData = { role: 'superadmin', email: key, name: 'Super Admin' };
    } else {
      const admin = await getAdmin(key);
      if (admin) {
        if (!verifyPassword(password, admin.passwordHash)) return res.status(401).json({ error: GENERIC });
        userData = { role: 'admin', email: key, name: admin.name };
      } else {
        const counsellor = await getCounsellor(key);
        if (counsellor) {
          if (!verifyPassword(password, counsellor.passwordHash)) return res.status(401).json({ error: GENERIC });
          userData = { role: 'counsellor', email: key, name: counsellor.name };
        } else {
          const user = await getUser(key);
          if (user && user.passwordHash) {
            if (!verifyPassword(password, user.passwordHash)) return res.status(401).json({ error: GENERIC });
            userData = { role: 'student', ...publicUser(user) };
          }
        }
      }
    }
    if (!userData) return res.status(401).json({ error: GENERIC });
    await loginSession(req, userData);
    res.json({ ok: true, user: req.session.user });
  } catch (err) { console.error('Login error:', err); res.status(500).json({ error: 'Login failed.' }); }
});

app.post('/api/auth/verify', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') return res.status(401).json({ error: 'Please sign in first.' });
  try {
    const verifyData = { ...req.body, submittedAt: Date.now(), verificationStatus: 'pending' };
    const user = await upsertUserDB({ email: req.session.user.email, verifyData });
    req.session.user = { role: 'student', ...publicUser(user) };
    res.json({ ok: true, user: req.session.user });
  } catch (err) { res.status(500).json({ error: 'Failed to update.' }); }
});

app.post('/api/auth/forgot-password', loginLimiter, async (req, res) => {
  const { email } = req.body || {};
  const key = (email || '').toLowerCase();
  const GENERIC_OK = { ok: true, message: 'If an account exists for that email, a reset link has been sent.' };
  if (!key || !/\S+@\S+\.\S+/.test(key)) return res.json(GENERIC_OK);
  try {
    // Check all sources
    let record = null, role = null;
    const user = await getUser(key);
    if (user && user.passwordHash) { record = user; role = 'student'; }
    if (!record) { const admin = await getAdmin(key); if (admin) { record = admin; role = 'admin'; } }
    if (!record) { const c = await getCounsellor(key); if (c) { record = c; role = 'counsellor'; } }
    if (!record) return res.json(GENERIC_OK);
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const tokens = readResetTokens();
    for (const t of Object.keys(tokens)) { if (tokens[t].email === key) delete tokens[t]; }
    tokens[tokenHash] = { email: key, role, expires: Date.now() + 60 * 60 * 1000 };
    writeResetTokens(tokens);
    const resetUrl = `${FRONTEND_URL}/reset-password?token=${rawToken}`;
    sendEmail({ to: key, subject: 'Reset your EduMitra password', html: resetPasswordEmailHtml(record.name, resetUrl) });
    res.json(GENERIC_OK);
  } catch (err) { res.json(GENERIC_OK); }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token) return res.status(400).json({ error: 'Invalid or missing reset token.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const tokens = readResetTokens();
  const entry = tokens[tokenHash];
  if (!entry) return res.status(400).json({ error: 'This reset link is invalid. Please request a new one.' });
  if (entry.expires < Date.now()) { delete tokens[tokenHash]; writeResetTokens(tokens); return res.status(400).json({ error: 'This reset link has expired. Please request a new one.' }); }
  try {
    const newHash = hashPassword(password);
    if (entry.role === 'admin') { const a = await getAdmin(entry.email); if (a) await saveAdmin({ ...a, passwordHash: newHash, passwordChangedAt: Date.now() }); }
    else if (entry.role === 'counsellor') { const c = await getCounsellor(entry.email); if (c) await saveCounsellor({ ...c, passwordHash: newHash, passwordChangedAt: Date.now() }); }
    else { const u = await getUser(entry.email); if (u) await saveUser({ ...u, passwordHash: newHash, passwordChangedAt: Date.now() }); }
    delete tokens[tokenHash]; writeResetTokens(tokens);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to reset password.' }); }
});

app.get('/auth/verify-session', (req, res) => {
  if (req.session.user) {
    const role = req.session.user.role;
    if (role === 'student' && req.session.user.approved) return res.redirect(`${FRONTEND_URL}/dashboard`);
    if (role === 'student') return res.redirect(`${FRONTEND_URL}/pending`);
    if (role === 'counsellor') return res.redirect(`${FRONTEND_URL}/counsellor`);
    if (role === 'admin' || role === 'superadmin') return res.redirect(`${FRONTEND_URL}/admin`);
  }
  res.redirect(`${FRONTEND_URL}/`);
});

app.get('/api/me', (req, res) => {
  if (req.session.user) return res.json({ loggedIn: true, user: req.session.user });
  res.json({ loggedIn: false });
});
app.post('/api/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });
app.get('/auth/logout', (req, res) => { req.session.destroy(() => res.redirect(`${FRONTEND_URL}/`)); });

/* ════════════════════════ PAYMENTS (Razorpay) ════════════════════════ */
let _razorpay = null;
function getRazorpay() { if (!_razorpay) { _razorpay = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID || '', key_secret: process.env.RAZORPAY_KEY_SECRET || '' }); } return _razorpay; }
function calcTotal(basePrice) { const base = parseFloat(basePrice); return Math.round(base * 1.03 * 1.18 * 100) / 100; }

app.post('/api/counsellor/fee', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'counsellor') return res.status(401).json({ error: 'Unauthorised.' });
  const { fee } = req.body || {};
  const parsed = parseFloat(fee);
  if (!parsed || parsed <= 0 || parsed > 100000) return res.status(400).json({ error: 'Invalid fee amount.' });
  try {
    const c = await getCounsellor(req.session.user.email);
    if (!c) return res.status(404).json({ error: 'Counsellor not found.' });
    await saveCounsellor({ ...c, sessionFee: parsed, feeStatus: 'pending', feeSubmittedAt: Date.now() });
    res.json({ ok: true, fee: parsed, feeStatus: 'pending' });
  } catch (err) { res.status(500).json({ error: 'Failed to update fee.' }); }
});

app.get('/api/counsellor/fee', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'counsellor') return res.status(401).json({ error: 'Unauthorised.' });
  try {
    const c = await getCounsellor(req.session.user.email);
    if (!c) return res.status(404).json({ error: 'Not found.' });
    res.json({ fee: c.sessionFee || null, feeStatus: c.feeStatus || null });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.get('/api/admin/fee-approvals', async (req, res) => {
  if (!req.session.user || !['admin','superadmin'].includes(req.session.user.role)) return res.status(401).json({ error: 'Unauthorised.' });
  try {
    const counsellors = await getAllCounsellors();
    const pending = Object.entries(counsellors).filter(([,c]) => c.feeStatus === 'pending').map(([email,c]) => ({ email, name: c.name, sessionFee: c.sessionFee, feeSubmittedAt: c.feeSubmittedAt }));
    res.json({ pending });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.post('/api/admin/counsellors/:email/fee', async (req, res) => {
  if (!req.session.user || !['admin','superadmin'].includes(req.session.user.role)) return res.status(401).json({ error: 'Unauthorised.' });
  const { action } = req.body || {};
  if (!['approve','reject'].includes(action)) return res.status(400).json({ error: 'action must be approve or reject.' });
  try {
    const key = decodeURIComponent(req.params.email).toLowerCase();
    const c = await getCounsellor(key);
    if (!c) return res.status(404).json({ error: 'Counsellor not found.' });
    await saveCounsellor({ ...c, feeStatus: action === 'approve' ? 'approved' : 'rejected', feeReviewedAt: Date.now() });
    res.json({ ok: true, feeStatus: action === 'approve' ? 'approved' : 'rejected' });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.get('/api/students/counsellors', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') return res.status(401).json({ error: 'Unauthorised.' });
  try {
    const counsellors = await getAllCounsellors();
    const list = Object.entries(counsellors).filter(([,c]) => c.feeStatus === 'approved' && c.sessionFee).map(([email,c]) => ({ email, name: c.name, sessionFee: c.sessionFee, total: calcTotal(c.sessionFee) }));
    res.json({ counsellors: list });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.post('/api/payment/create-order', async (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') return res.status(401).json({ error: 'Unauthorised.' });
  const { counsellorEmail } = req.body || {};
  try {
    const c = await getCounsellor((counsellorEmail || '').toLowerCase());
    if (!c || c.feeStatus !== 'approved' || !c.sessionFee) return res.status(400).json({ error: 'Counsellor fee not available.' });
    const totalRupees = calcTotal(c.sessionFee);
    const order = await getRazorpay().orders.create({ amount: Math.round(totalRupees * 100), currency: 'INR', receipt: `rcpt_${Date.now()}`, notes: { studentEmail: req.session.user.email, counsellorEmail } });
    res.json({ ok: true, orderId: order.id, amount: Math.round(totalRupees * 100), amountDisplay: totalRupees, currency: 'INR', counsellorName: c.name, counsellorEmail, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (e) { console.error('[razorpay] error:', e?.error || e?.message || JSON.stringify(e)); res.status(500).json({ error: 'Could not create payment order. Please try again.' }); }
});

app.post('/api/payment/verify', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'student') return res.status(401).json({ error: 'Unauthorised.' });
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) return res.status(400).json({ error: 'Missing payment details.' });
  const expectedSig = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || '').update(`${razorpay_order_id}|${razorpay_payment_id}`).digest('hex');
  if (expectedSig !== razorpay_signature) return res.status(400).json({ error: 'Payment verification failed.' });
  res.json({ ok: true, paymentId: razorpay_payment_id });
});

/* ════════════════════════ ADMIN ════════════════════════ */
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const key = (email || '').toLowerCase();
    const GENERIC = 'Invalid email or password.';
    let userData = null;
    if (SUPERADMIN_EMAIL && key === SUPERADMIN_EMAIL) {
      if (password !== SUPERADMIN_PASSWORD) return res.status(401).json({ error: GENERIC });
      userData = { role: 'superadmin', email: key, name: 'Super Admin' };
    } else {
      const admin = await getAdmin(key);
      if (!admin || !verifyPassword(password || '', admin.passwordHash)) return res.status(401).json({ error: GENERIC });
      userData = { role: 'admin', email: key, name: admin.name };
    }
    await loginSession(req, userData);
    res.json({ ok: true, user: req.session.user });
  } catch (err) { res.status(500).json({ error: 'Login failed.' }); }
});

app.get('/api/admin/me', (req, res) => {
  if (req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'superadmin')) return res.json({ loggedIn: true, user: req.session.user });
  res.json({ loggedIn: false });
});

app.get('/api/admin/students', requireAdmin, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try { const users = await getAllUsers(); res.json({ students: Object.values(users).map(publicUser) }); }
  catch (err) { res.status(500).json({ error: 'Failed to load students.' }); }
});

app.post('/api/admin/students/:email/approve', requireAdmin, async (req, res) => {
  try {
    const key = req.params.email.toLowerCase();
    const user = await getUser(key);
    if (!user) return res.status(404).json({ error: 'Student not found.' });
    const wasAlreadyApproved = user.approved === true;
    const updated = await upsertUserDB({ email: key, approved: true, verifyData: { ...(user.verifyData || {}), verificationStatus: 'approved' }, adminNote: req.body?.note || '', assignedCounsellorEmail: (req.body?.assignedCounsellorEmail || '').toLowerCase() || null, approvedAt: new Date().toISOString() });
    if (!wasAlreadyApproved) sendEmail({ to: updated.email, subject: 'Your EduMitra account is approved', html: approvalEmailHtml(updated.name, `${FRONTEND_URL}/dashboard`) });
    res.json({ ok: true });
  } catch (err) { console.error('Approve error:', err); res.status(500).json({ error: 'Failed.' }); }
});

app.post('/api/admin/students/:email/reject', requireAdmin, async (req, res) => {
  try {
    const key = req.params.email.toLowerCase();
    const user = await getUser(key);
    if (!user) return res.status(404).json({ error: 'Student not found.' });
    await upsertUserDB({ email: key, approved: false, verifyData: { ...(user.verifyData || {}), verificationStatus: 'rejected' }, adminNote: req.body?.note || '' });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const usersMap = await getAllUsers();
    const users = Object.values(usersMap);
    let pending = 0, approved = 0, rejected = 0;
    users.forEach(u => { if (u.approved) approved++; else if (u.verifyData?.verificationStatus === 'rejected') rejected++; else pending++; });
    const days = []; for (let i = 13; i >= 0; i--) { const d = new Date(); d.setDate(d.getDate() - i); days.push({ date: d.toISOString().slice(0, 10), count: 0 }); }
    users.forEach(u => { if (!u.registeredAt) return; const day = new Date(u.registeredAt).toISOString().slice(0, 10); const bucket = days.find(d => d.date === day); if (bucket) bucket.count++; });
    const recent = users.filter(u => u.registeredAt).sort((a, b) => b.registeredAt - a.registeredAt).slice(0, 8).map(publicUser);
    res.json({ total: users.length, pending, approved, rejected, signupsByDay: days, recent });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

/* ════════════════════════ SUPER ADMIN — admins ════════════════════════ */
app.get('/api/superadmin/admins', requireSuperAdmin, async (req, res) => {
  try { const admins = await getAllAdmins(); res.json({ admins: Object.values(admins).map(({ passwordHash, ...safe }) => safe), superAdminEmail: SUPERADMIN_EMAIL }); }
  catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.post('/api/superadmin/admins', requireSuperAdmin, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid name and email.' });
    if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    const key = email.toLowerCase();
    if (key === SUPERADMIN_EMAIL) return res.status(409).json({ error: 'That email is reserved.' });
    const existing = await getAdmin(key);
    if (existing) return res.status(409).json({ error: 'An admin with this email already exists.' });
    await saveAdmin({ name, email: key, passwordHash: hashPassword(password), createdAt: Date.now() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.delete('/api/superadmin/admins/:email', requireSuperAdmin, async (req, res) => {
  try { await deleteAdmin(req.params.email.toLowerCase()); res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

/* ════════════════════════ SUPER ADMIN — counsellors ════════════════════════ */
app.get('/api/superadmin/counsellors', requireSuperAdmin, async (req, res) => {
  try { const all = await getAllCounsellors(); const list = Object.values(all).map(({ passwordHash, google, ...safe }) => ({ ...safe, calendarConnected: !!(google && google.refreshToken) })); res.json({ counsellors: list }); }
  catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.post('/api/superadmin/counsellors', requireSuperAdmin, async (req, res) => {
  try {
    const { name, email } = req.body || {};
    if (!name || !name.trim()) return res.status(400).json({ error: "Please enter the counsellor's name." });
    if (!email || !/\S+@\S+\.\S+/.test(email)) return res.status(400).json({ error: 'Please enter a valid email.' });
    const key = email.toLowerCase();
    if (key === SUPERADMIN_EMAIL) return res.status(409).json({ error: 'That email is reserved.' });
    const existing = await getCounsellor(key);
    if (existing) return res.status(409).json({ error: 'A counsellor with this email already exists.' });
    const existingAdmin = await getAdmin(key);
    if (existingAdmin) return res.status(409).json({ error: 'That email is already used by an admin account.' });
    const tempPassword = generatePassword();
    await saveCounsellor({ name: name.trim(), email: key, passwordHash: hashPassword(tempPassword), createdAt: Date.now(), createdBy: req.session.user.email });
    try { await sendEmail({ to: key, subject: 'Welcome to EduMitra — your counsellor account is ready', html: counsellorWelcomeEmailHtml(name.trim(), key, tempPassword, `${FRONTEND_URL}/counsellor-login`) }); res.json({ ok: true, emailed: true }); }
    catch (err) { res.json({ ok: true, emailed: false, tempPassword, note: 'Account created but welcome email failed. Share credentials manually.' }); }
  } catch (err) { console.error('Create counsellor error:', err); res.status(500).json({ error: 'Failed.' }); }
});
app.delete('/api/superadmin/counsellors/:email', requireSuperAdmin, async (req, res) => {
  try {
    const key = req.params.email.toLowerCase();
    await deleteCounsellor(key);
    // Delete counsellor's slots
    const slots = await getAllSlots();
    for (const [id, s] of Object.entries(slots)) { if (s.counsellorEmail === key) await deleteSlot(id); }
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

/* ════════════════════════ COUNSELLOR AUTH ════════════════════════ */
app.post('/api/counsellor/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const key = (email || '').toLowerCase();
    const counsellor = await getCounsellor(key);
    const GENERIC = 'Invalid email or password.';
    if (!counsellor || !verifyPassword(password || '', counsellor.passwordHash)) return res.status(401).json({ error: GENERIC });
    await loginSession(req, { role: 'counsellor', email: key, name: counsellor.name });
    res.json({ ok: true, user: req.session.user });
  } catch (err) { res.status(500).json({ error: 'Login failed.' }); }
});
app.get('/api/counsellor/me', (req, res) => {
  if (req.session.user && req.session.user.role === 'counsellor') return res.json({ loggedIn: true, user: req.session.user });
  res.json({ loggedIn: false });
});
app.post('/api/counsellor/change-password', requireCounsellor, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword) return res.status(400).json({ error: 'Please enter your current password.' });
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    if (newPassword === currentPassword) return res.status(400).json({ error: 'New password must be different.' });
    const c = await getCounsellor(req.session.user.email);
    if (!c) return res.status(404).json({ error: 'Counsellor not found.' });
    if (!verifyPassword(currentPassword, c.passwordHash)) return res.status(401).json({ error: 'Current password is incorrect.' });
    await saveCounsellor({ ...c, passwordHash: hashPassword(newPassword), passwordChangedAt: Date.now() });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

/* ════════════════════════ GOOGLE CALENDAR ════════════════════════ */
function getOAuth2Client() { return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET, process.env.GOOGLE_CALENDAR_REDIRECT_URI || `${FRONTEND_URL}/auth/google/calendar/callback`); }

async function getCalendarForCounsellor(counsellorEmail) {
  const c = await getCounsellor(counsellorEmail.toLowerCase());
  if (!c || !c.google || !c.google.refreshToken) throw new Error('Counsellor has not connected Google Calendar.');
  const oauth2 = getOAuth2Client();
  oauth2.setCredentials({ refresh_token: c.google.refreshToken, access_token: c.google.accessToken, expiry_date: c.google.expiry });
  oauth2.on('tokens', async (tokens) => {
    try {
      const fresh = await getCounsellor(counsellorEmail.toLowerCase());
      if (!fresh) return;
      await saveCounsellor({ ...fresh, google: { ...fresh.google, accessToken: tokens.access_token || fresh.google.accessToken, expiry: tokens.expiry_date || fresh.google.expiry, refreshToken: tokens.refresh_token || fresh.google.refreshToken } });
    } catch (e) {}
  });
  return google.calendar({ version: 'v3', auth: oauth2 });
}

app.get('/auth/google/calendar', requireCounsellor, (req, res) => {
  const oauth2 = getOAuth2Client();
  const url = oauth2.generateAuthUrl({ access_type: 'offline', prompt: 'consent', scope: ['https://www.googleapis.com/auth/calendar.events', 'https://www.googleapis.com/auth/calendar.readonly'], state: req.session.user.email });
  res.redirect(url);
});
app.get('/auth/google/calendar/callback', async (req, res) => {
  try {
    if (!req.session.user || req.session.user.role !== 'counsellor') return res.redirect(`${FRONTEND_URL}/counsellor-login?cal_error=auth`);
    const { code, state } = req.query;
    if (!code) return res.redirect(`${FRONTEND_URL}/counsellor?cal_error=no_code`);
    if (state !== req.session.user.email) return res.redirect(`${FRONTEND_URL}/counsellor?cal_error=state`);
    const oauth2 = getOAuth2Client();
    const { tokens } = await oauth2.getToken(code);
    const c = await getCounsellor(req.session.user.email);
    if (!c) return res.redirect(`${FRONTEND_URL}/counsellor?cal_error=no_counsellor`);
    await saveCounsellor({ ...c, google: { refreshToken: tokens.refresh_token || c.google?.refreshToken, accessToken: tokens.access_token, expiry: tokens.expiry_date, tokenType: tokens.token_type, scope: tokens.scope, connectedAt: Date.now() } });
    res.redirect(`${FRONTEND_URL}/counsellor?cal_success=1`);
  } catch (err) { console.error('Calendar OAuth error:', err); res.redirect(`${FRONTEND_URL}/counsellor?cal_error=token`); }
});
app.post('/api/counsellor/calendar/disconnect', requireCounsellor, async (req, res) => {
  try { const c = await getCounsellor(req.session.user.email); if (c) { const { google: _g, ...rest } = c; await saveCounsellor(rest); } res.json({ ok: true }); }
  catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.get('/api/counsellor/calendar/status', requireCounsellor, async (req, res) => {
  try { const c = await getCounsellor(req.session.user.email); res.json({ connected: !!(c && c.google && c.google.refreshToken) }); }
  catch (err) { res.json({ connected: false }); }
});

/* ════════════════════════ SLOTS — counsellor side ════════════════════════ */
app.get('/api/counsellor/slots', requireCounsellor, async (req, res) => {
  try { const all = await getAllSlots(); const slots = Object.values(all).filter(s => s.counsellorEmail === req.session.user.email).sort((a, b) => (a.date + a.startTime).localeCompare(b.date + b.startTime)); res.json({ slots }); }
  catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.post('/api/counsellor/slots', requireCounsellor, async (req, res) => {
  const { date, startTime, endTime, label } = req.body || {};
  if (!date || !startTime || !endTime) return res.status(400).json({ error: 'Date, start time and end time are required.' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Date must be in YYYY-MM-DD format.' });
  if (startTime >= endTime) return res.status(400).json({ error: 'End time must be after start time.' });
  try {
    const c = await getCounsellor(req.session.user.email);
    if (!c || !c.google || !c.google.refreshToken) return res.status(400).json({ error: 'Please connect your Google Calendar first.' });
    const id = Date.now();
    await saveSlot({ id, counsellorEmail: req.session.user.email, date, startTime, endTime, label: (label || '').trim() || 'General Counselling', booked: false, createdAt: Date.now() });
    res.json({ ok: true, slot: { id, counsellorEmail: req.session.user.email, date, startTime, endTime, label: (label || '').trim() || 'General Counselling', booked: false } });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.delete('/api/counsellor/slots/:id', requireCounsellor, async (req, res) => {
  try {
    const all = await getAllSlots();
    const slot = all[req.params.id];
    if (!slot) return res.status(404).json({ error: 'Slot not found.' });
    if (slot.counsellorEmail !== req.session.user.email) return res.status(403).json({ error: 'Not your slot.' });
    if (slot.booked && slot.googleEventId) {
      try { const cal = await getCalendarForCounsellor(slot.counsellorEmail); await cal.events.delete({ calendarId: 'primary', eventId: slot.googleEventId, sendUpdates: 'all' }); } catch (e) { console.warn('Could not delete calendar event:', e.message); }
    }
    await deleteSlot(req.params.id);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

/* ════════════════════════ SLOTS — student side ════════════════════════ */
app.get('/api/student/slots', requireStudent, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const [allSlots, counsellors] = await Promise.all([getAllSlots(), getAllCounsellors()]);
    const slots = Object.values(allSlots).filter(s => !s.booked && s.date >= today).sort((a, b) => (a.date + a.startTime).localeCompare(b.date + b.startTime)).map(s => ({ ...s, counsellorName: counsellors[s.counsellorEmail]?.name || 'Counsellor' }));
    res.json({ slots });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.get('/api/student/bookings', requireStudent, async (req, res) => {
  try {
    const [allSlots, counsellors] = await Promise.all([getAllSlots(), getAllCounsellors()]);
    const list = Object.values(allSlots).filter(s => s.bookedBy === req.session.user.email).sort((a, b) => (b.date + b.startTime).localeCompare(a.date + a.startTime)).map(s => ({ ...s, counsellorName: counsellors[s.counsellorEmail]?.name || 'Counsellor' }));
    res.json({ bookings: list });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});
app.post('/api/student/book/:slotId', requireStudent, async (req, res) => {
  try {
    const [allSlots, student] = await Promise.all([getAllSlots(), getUser(req.session.user.email)]);
    const slot = allSlots[req.params.slotId];
    if (!slot) return res.status(404).json({ error: 'Slot not found.' });
    if (slot.booked) return res.status(409).json({ error: 'This slot has already been booked.' });
    if (!student || !student.approved) return res.status(403).json({ error: 'Your account must be approved before booking sessions.' });
    const counsellor = await getCounsellor(slot.counsellorEmail);
    if (!counsellor) return res.status(404).json({ error: 'Counsellor not found.' });
    const calendar = await getCalendarForCounsellor(slot.counsellorEmail);
    const event = await calendar.events.insert({ calendarId: 'primary', conferenceDataVersion: 1, sendUpdates: 'all', requestBody: { summary: `EduMitra Counselling: ${student.name || student.email}`, description: `Counselling session via EduMitra.\nCounsellor: ${counsellor.name}\nStudent: ${student.name || student.email}\nTopic: ${slot.label || 'General Counselling'}`, start: { dateTime: `${slot.date}T${slot.startTime}:00`, timeZone: 'Asia/Kolkata' }, end: { dateTime: `${slot.date}T${slot.endTime}:00`, timeZone: 'Asia/Kolkata' }, attendees: [{ email: student.email }, { email: slot.counsellorEmail }], conferenceData: { createRequest: { requestId: `edumitra-${slot.id}-${Date.now()}`, conferenceSolutionKey: { type: 'hangoutsMeet' } } } } });
    const meetLink = event.data.hangoutLink || event.data.conferenceData?.entryPoints?.find(e => e.entryPointType === 'video')?.uri || null;
    await saveSlot({ ...slot, booked: true, bookedBy: student.email, googleEventId: event.data.id, meetLink });
    const emailHtml = bookingEmailHtml({ studentName: student.name || student.email, counsellorName: counsellor.name, date: slot.date, startTime: slot.startTime, endTime: slot.endTime, label: slot.label, meetLink });
    sendEmail({ to: student.email, subject: 'Your EduMitra session is booked', html: emailHtml });
    sendEmail({ to: slot.counsellorEmail, subject: `New session booked by ${student.name || student.email}`, html: emailHtml });
    res.json({ ok: true, meetLink, slot });
  } catch (err) { console.error('Booking error:', err); res.status(500).json({ error: 'Could not create Google Meet event: ' + (err.message || 'unknown error') }); }
});

/* ════════════════════════ COUNSELLOR — students ════════════════════════ */
app.get('/api/counsellor/students', requireCounsellor, async (req, res) => {
  try {
    const users = await getAllUsers();
    const students = Object.values(users).filter(u => u.approved && u.assignedCounsellorEmail === req.session.user.email).map(publicUser).sort((a, b) => (b.approvedAt || 0) > (a.approvedAt || 0) ? 1 : -1);
    res.json({ students });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.post('/api/counsellor/schedule-meet', requireCounsellor, async (req, res) => {
  const { studentEmail, date, time, duration, sessionNum, sessionType, agenda } = req.body || {};
  if (!studentEmail || !date || !time) return res.status(400).json({ error: 'studentEmail, date, and time are required.' });
  try {
    const [counsellor, student] = await Promise.all([getCounsellor(req.session.user.email), getUser(studentEmail.toLowerCase())]);
    if (!counsellor) return res.status(404).json({ error: 'Counsellor not found.' });
    if (!student) return res.status(404).json({ error: 'Student not found.' });
    if (!counsellor.google || !counsellor.google.refreshToken) return res.status(400).json({ error: 'Please connect your Google Calendar first.' });
    const durationMins = parseInt(duration || 60, 10);
    const endDate = new Date(`${date}T${time}:00`); endDate.setMinutes(endDate.getMinutes() + durationMins);
    const calendar = await getCalendarForCounsellor(req.session.user.email);
    const event = await calendar.events.insert({ calendarId: 'primary', conferenceDataVersion: 1, sendUpdates: 'all', requestBody: { summary: `EduMitra Session #${sessionNum || '?'}: ${student.name || student.email}`, description: `EduMitra counselling session.\nCounsellor: ${counsellor.name}\nStudent: ${student.name || student.email}\nType: ${sessionType || 'General Counselling'}\n${agenda ? '\nAgenda:\n' + agenda : ''}`, start: { dateTime: `${date}T${time}:00`, timeZone: 'Asia/Kolkata' }, end: { dateTime: endDate.toISOString().slice(0, 19), timeZone: 'Asia/Kolkata' }, attendees: [{ email: student.email }, { email: req.session.user.email }], conferenceData: { createRequest: { requestId: `edumitra-${Date.now()}`, conferenceSolutionKey: { type: 'hangoutsMeet' } } } } });
    const meetLink = event.data.hangoutLink || event.data.conferenceData?.entryPoints?.find(e => e.entryPointType === 'video')?.uri || null;
    if (meetLink) {
      const dateStr = new Date(`${date}T${time}:00`).toLocaleDateString('en-IN', { weekday:'long', day:'numeric', month:'long', year:'numeric' });
      const html = `<!DOCTYPE html><html><body style="font-family:Inter,Arial,sans-serif;color:#0a1628;padding:40px 20px;"><div style="max-width:520px;margin:0 auto;background:#fff;padding:36px;border-radius:12px;"><h2>Your EduMitra Session is Confirmed</h2><p>Hi ${student.name || 'there'},</p><p>Your session with <strong>${counsellor.name}</strong> on <strong>${dateStr}</strong> is scheduled.</p><p><a href="${meetLink}" style="display:inline-block;padding:12px 24px;background:#0a1628;color:#fff;text-decoration:none;border-radius:8px;font-weight:700;">Join Google Meet</a></p></div></body></html>`;
      sendEmail({ to: student.email, subject: `Your EduMitra session is confirmed — ${dateStr}`, html });
      sendEmail({ to: req.session.user.email, subject: `Session confirmed with ${student.name || student.email}`, html });
    }
    res.json({ ok: true, meetLink, eventId: event.data.id });
  } catch (err) { console.error('[schedule-meet] error:', err); res.status(500).json({ error: 'Could not create Google Meet event: ' + (err.message || 'unknown error') }); }
});

/* ════════════════════════ REFERRALS ════════════════════════ */
function getReferralCode(email) { const local = email.split('@')[0].replace(/[^a-zA-Z0-9]/g, '').toUpperCase().slice(0, 4); let hash = 0; for (let i = 0; i < email.length; i++) hash = (hash * 31 + email.charCodeAt(i)) & 0xffff; return 'EDU' + local + String(hash).slice(-3).padStart(3, '0'); }

app.get('/api/student/referrals', requireStudent, async (req, res) => {
  try {
    const email = req.session.user.email;
    const refCode = getReferralCode(email);
    const [usersMap, allSlots] = await Promise.all([getAllUsers(), getAllSlots()]);
    const referred = Object.values(usersMap).filter(u => u.referredBy === refCode);
    const referrals = referred.map(u => { const firstBooking = Object.values(allSlots).find(s => s.bookedBy === u.email); return { name: u.name || u.email, email: u.email, referredAt: u.registeredAt, status: firstBooking ? 'completed' : (u.approved ? 'signed_up' : 'pending') }; });
    res.json({ referralCode: refCode, referrals, totalEarned: referrals.filter(r => r.status === 'completed').length * 500 });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.get('/api/referral/validate/:code', async (req, res) => {
  const code = (req.params.code || '').toUpperCase().trim();
  if (!code) return res.status(400).json({ error: 'No code provided.' });
  try {
    const users = await getAllUsers();
    const owner = Object.values(users).find(u => getReferralCode(u.email) === code);
    if (!owner) return res.status(404).json({ valid: false, error: 'Invalid referral code.' });
    if (req.session.user && req.session.user.email === owner.email) return res.status(400).json({ valid: false, error: 'You cannot use your own referral code.' });
    res.json({ valid: true, discount: 250, ownerName: owner.name || 'an EduMitra user' });
  } catch (err) { res.status(500).json({ error: 'Failed.' }); }
});

app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
