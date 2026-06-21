require('dotenv').config();
const express    = require('express');
const session    = require('express-session');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const rateLimit  = require('express-rate-limit');
const nodemailer = require('nodemailer');

const app  = express();
const PORT = process.env.PORT || 5000;
const FRONTEND_URL       = process.env.FRONTEND_URL       || `http://localhost:${PORT}`;
const GOOGLE_CLIENT_ID   = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI  = process.env.GOOGLE_REDIRECT_URI  || `${FRONTEND_URL}/auth/google/callback`;
const LINKEDIN_CLIENT_ID   = process.env.LINKEDIN_CLIENT_ID;
const LINKEDIN_CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const LINKEDIN_REDIRECT_URI  = process.env.LINKEDIN_REDIRECT_URI || `${FRONTEND_URL}/auth/linkedin/callback`;
const SUPERADMIN_EMAIL   = (process.env.SUPERADMIN_EMAIL   || '').toLowerCase();
const SUPERADMIN_PASSWORD = process.env.SUPERADMIN_PASSWORD || '';

// ── Data files ──────────────────────────────────────────────────────────────
const DATA_DIR   = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ADMINS_FILE = path.join(DATA_DIR, 'admins.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE))  fs.writeFileSync(USERS_FILE,  '{}', 'utf8');
if (!fs.existsSync(ADMINS_FILE)) fs.writeFileSync(ADMINS_FILE, '{}', 'utf8');

function readUsers()  { try { return JSON.parse(fs.readFileSync(USERS_FILE,  'utf8')); } catch { return {}; } }
function writeUsers(u)  { fs.writeFileSync(USERS_FILE,  JSON.stringify(u,  null, 2), 'utf8'); }
function readAdmins() { try { return JSON.parse(fs.readFileSync(ADMINS_FILE, 'utf8')); } catch { return {}; } }
function writeAdmins(a) { fs.writeFileSync(ADMINS_FILE, JSON.stringify(a, null, 2), 'utf8'); }

// ── Password helpers ─────────────────────────────────────────────────────────
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(plain, stored) {
  try {
    const [salt, hash] = stored.split(':');
    const attempt = crypto.scryptSync(plain, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(attempt, 'hex'));
  } catch { return false; }
}

function publicUser(u) {
  const { passwordHash, ...safe } = u;
  return safe;
}

// ── Zepto Mail (nodemailer SMTP) ─────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  host:   process.env.ZEPTO_HOST || 'smtp.zeptomail.in',
  port:   parseInt(process.env.ZEPTO_PORT || '587', 10),
  secure: false,
  auth: {
    user: process.env.ZEPTO_USER,
    pass: process.env.ZEPTO_PASS,
  },
});

if (process.env.ZEPTO_USER) {
  mailer.verify((err) => {
    if (err) console.error('[mail] Zepto Mail not reachable:', err.message);
    else     console.log('[mail] Zepto Mail SMTP ready');
  });
} else {
  console.warn('[mail] ZEPTO_USER not set — emails disabled');
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ── Email footer shared block ────────────────────────────────────────────────
function emailServicesBlock() {
  return `
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:32px;border-top:1px solid #e8e3da;padding-top:24px;">
      <tr>
        <td style="padding:0 0 16px 0;">
          <p style="margin:0 0 6px 0;font-size:13px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;">What all can you do with EduMitra?</p>
        </td>
      </tr>
      <tr>
        <td style="padding:0 0 12px 0;">
          <p style="margin:0 0 4px 0;font-size:13px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;">Study Abroad Application</p>
          <p style="margin:0;font-size:12px;color:#555;font-family:Arial,sans-serif;line-height:1.5;">Personalised end-to-end study abroad, visa assistance, SOPs, best university selection, scholarships, interview preparation, and more.</p>
        </td>
      </tr>
      <tr>
        <td style="padding:0 0 12px 0;">
          <p style="margin:0 0 4px 0;font-size:13px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;">Job Placement Assistance</p>
          <p style="margin:0;font-size:12px;color:#555;font-family:Arial,sans-serif;line-height:1.5;">Interview line-up assistance, professional resume, cover letter, online profiling, interview preparation, career assessment, and more.</p>
        </td>
      </tr>
      <tr>
        <td style="padding:0 0 12px 0;">
          <p style="margin:0 0 4px 0;font-size:13px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;">Job Transition</p>
          <p style="margin:0;font-size:12px;color:#555;font-family:Arial,sans-serif;line-height:1.5;">Personalised guidance for career transitions, skills assessment, industry-specific coaching, and placement support tailored to your goals.</p>
        </td>
      </tr>
      <tr>
        <td style="padding-top:16px;border-top:1px solid #e8e3da;">
          <p style="margin:0;font-size:11px;color:#999;font-family:Arial,sans-serif;">You received this email because you signed-up on EduMitra platform for our services &nbsp;|&nbsp; &copy; Funds And Toil Private Limited (EduMitra) | Made with love in India</p>
        </td>
      </tr>
    </table>
  `;
}

// ── Welcome email (buyer's template) ─────────────────────────────────────────
function welcomeEmailHtml(name) {
  const firstName = escapeHtml((name || 'there').split(' ')[0]);
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f1ea;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea;padding:32px 16px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
          <!-- Header -->
          <tr>
            <td style="background:#0a1628;padding:28px 40px;">
              <p style="margin:0;font-size:22px;font-weight:700;color:#faf7f2;font-family:Arial,sans-serif;letter-spacing:-0.3px;">EduMitra</p>
              <p style="margin:4px 0 0 0;font-size:12px;color:#a0aec0;font-family:Arial,sans-serif;">by Funds And Toil Private Limited</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:36px 40px 28px 40px;">
              <p style="margin:0 0 16px 0;font-size:16px;color:#0a1628;font-family:Arial,sans-serif;">Dear ${firstName},</p>

              <p style="margin:0 0 16px 0;font-size:15px;color:#333;line-height:1.7;font-family:Arial,sans-serif;">
                Thank you for signing up, and welcome to <strong>EduMitra</strong> — where global education and career transitions become clearer and more achievable.
              </p>

              <p style="margin:0 0 16px 0;font-size:15px;color:#333;line-height:1.7;font-family:Arial,sans-serif;">
                Whether you are exploring study-abroad options, planning a job transition, or seeking placement assistance, our experts are ready to guide you.
              </p>

              <p style="margin:0 0 24px 0;font-size:15px;color:#333;line-height:1.7;font-family:Arial,sans-serif;">
                We have received your details and we will be in touch shortly to discuss your goals and next steps. If you have any immediate questions, reply to this email and we will respond quickly.
              </p>

              <!-- Next steps box -->
              <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea;border-radius:8px;padding:20px 24px;margin-bottom:24px;">
                <tr>
                  <td>
                    <p style="margin:0 0 8px 0;font-size:13px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;text-transform:uppercase;letter-spacing:0.5px;">Next Steps</p>
                    <p style="margin:0;font-size:13px;color:#555;font-family:Arial,sans-serif;line-height:1.6;">Once your account is approved, you can update your profile and upload documents directly from your dashboard.</p>
                  </td>
                </tr>
              </table>

              <p style="margin:0 0 4px 0;font-size:15px;color:#333;font-family:Arial,sans-serif;">Warm regards,</p>
              <p style="margin:0;font-size:15px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;">The EduMitra Team</p>

              ${emailServicesBlock()}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ── Approval email (branded, no buyer template provided) ─────────────────────
function approvalEmailHtml(name) {
  const firstName = escapeHtml((name || 'there').split(' ')[0]);
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f1ea;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea;padding:32px 16px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);">
          <tr>
            <td style="background:#0a1628;padding:28px 40px;">
              <p style="margin:0;font-size:22px;font-weight:700;color:#faf7f2;font-family:Arial,sans-serif;letter-spacing:-0.3px;">EduMitra</p>
              <p style="margin:4px 0 0 0;font-size:12px;color:#a0aec0;font-family:Arial,sans-serif;">by Funds And Toil Private Limited</p>
            </td>
          </tr>
          <tr>
            <td style="padding:36px 40px 28px 40px;">
              <p style="margin:0 0 16px 0;font-size:16px;color:#0a1628;font-family:Arial,sans-serif;">Dear ${firstName},</p>

              <p style="margin:0 0 16px 0;font-size:15px;color:#333;line-height:1.7;font-family:Arial,sans-serif;">
                Great news — your EduMitra account has been <strong style="color:#16a34a;">approved</strong>! You can now log in and access your personal dashboard.
              </p>

              <table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
                <tr>
                  <td align="center">
                    <a href="${FRONTEND_URL}/dashboard.html"
                       style="display:inline-block;background:#0a1628;color:#faf7f2;text-decoration:none;
                              padding:14px 32px;border-radius:8px;font-size:14px;font-weight:700;
                              font-family:Arial,sans-serif;letter-spacing:0.2px;">
                      Go to My Dashboard →
                    </a>
                  </td>
                </tr>
              </table>

              <p style="margin:0 0 16px 0;font-size:14px;color:#555;line-height:1.7;font-family:Arial,sans-serif;">
                From your dashboard you can update your profile, upload documents, and book counselling sessions once available.
              </p>

              <p style="margin:0 0 4px 0;font-size:15px;color:#333;font-family:Arial,sans-serif;">Warm regards,</p>
              <p style="margin:0;font-size:15px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;">The EduMitra Team</p>

              ${emailServicesBlock()}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ── Send helper ───────────────────────────────────────────────────────────────
async function sendEmail({ to, subject, html }) {
  if (!process.env.ZEPTO_USER) {
    console.warn('[mail] ZEPTO_USER not set — skipping email to', to);
    return;
  }
  try {
    await mailer.sendMail({ from: process.env.ZEPTO_FROM, to, subject, html });
    console.log('[mail] sent to', to, '·', subject);
  } catch (err) {
    console.error('[mail] failed to', to, '·', err.message);
  }
}

// ── Rate limiters ─────────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: 'Too many sign-up attempts from this IP. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ── Express setup ─────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}));

// Serve static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth helpers ──────────────────────────────────────────────────────────────
function requireStudent(req, res, next) {
  if (req.session.user?.role === 'student') return next();
  res.status(401).json({ error: 'Not authenticated as student.' });
}
function requireAdmin(req, res, next) {
  if (['admin', 'superadmin'].includes(req.session.user?.role)) return next();
  res.status(401).json({ error: 'Not authenticated as admin.' });
}

// ── /api/me ───────────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, user: req.session.user });
});

// ── Student auth ──────────────────────────────────────────────────────────────
app.post('/api/auth/signup', signupLimiter, (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password are required.' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const users = readUsers();
  const key = email.toLowerCase();
  if (users[key]) return res.status(409).json({ error: 'An account already exists for this email.' });

  users[key] = {
    name,
    email: key,
    passwordHash: hashPassword(password),
    approved: false,
    provider: 'email',
    registeredAt: Date.now(),
  };
  writeUsers(users);

  req.session.user = { role: 'student', ...publicUser(users[key]) };

  // Fire-and-forget welcome email
  sendEmail({
    to: key,
    subject: 'Welcome to EduMitra',
    html: welcomeEmailHtml(name),
  });

  res.json({ ok: true, user: req.session.user });
});

app.post('/api/auth/login', loginLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const GENERIC = 'Invalid email or password.';
  const users = readUsers();
  const user = users[(email || '').toLowerCase()];
  if (!user)             return res.status(401).json({ error: GENERIC });
  if (!user.passwordHash) return res.status(401).json({ error: GENERIC });
  if (!verifyPassword(password || '', user.passwordHash)) return res.status(401).json({ error: GENERIC });

  req.session.user = { role: 'student', ...publicUser(user) };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get('/auth/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// ── Forgot password ───────────────────────────────────────────────────────────
const resetTokens = {}; // { token: { email, expires } }

app.post('/api/auth/forgot-password', loginLimiter, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  const key = email.toLowerCase();
  const users = readUsers();

  // Always return the same response to prevent email enumeration
  res.json({ ok: true, message: 'If that email is registered, a reset link has been sent.' });

  if (!users[key] || !users[key].passwordHash) return; // OAuth-only account or not found

  const token = crypto.randomBytes(32).toString('hex');
  resetTokens[token] = { email: key, expires: Date.now() + 60 * 60 * 1000 }; // 1 hour

  const resetLink = `${FRONTEND_URL}/reset-password.html?token=${token}`;

  sendEmail({
    to: key,
    subject: 'Reset your EduMitra password',
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f4f1ea;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f1ea;padding:32px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">
        <tr><td style="background:#0a1628;padding:28px 40px;">
          <p style="margin:0;font-size:22px;font-weight:700;color:#faf7f2;font-family:Arial,sans-serif;">EduMitra</p>
          <p style="margin:4px 0 0;font-size:12px;color:#a0aec0;font-family:Arial,sans-serif;">by Funds And Toil Private Limited</p>
        </td></tr>
        <tr><td style="padding:36px 40px 28px;">
          <p style="margin:0 0 16px;font-size:15px;color:#333;line-height:1.7;font-family:Arial,sans-serif;">
            We received a request to reset your EduMitra password. Click the button below to choose a new password.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0" style="margin:24px 0;">
            <tr><td align="center">
              <a href="${resetLink}"
                 style="display:inline-block;background:#0a1628;color:#faf7f2;text-decoration:none;
                        padding:14px 32px;border-radius:8px;font-size:14px;font-weight:700;font-family:Arial,sans-serif;">
                Reset Password →
              </a>
            </td></tr>
          </table>
          <p style="margin:0 0 16px;font-size:13px;color:#888;line-height:1.6;font-family:Arial,sans-serif;">
            This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email — your password will not change.
          </p>
          <p style="margin:0 0 4px;font-size:15px;color:#333;font-family:Arial,sans-serif;">Warm regards,</p>
          <p style="margin:0;font-size:15px;font-weight:700;color:#0a1628;font-family:Arial,sans-serif;">The EduMitra Team</p>
          ${emailServicesBlock()}
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
  });
});

app.post('/api/auth/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password)
    return res.status(400).json({ error: 'Token and new password are required.' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const record = resetTokens[token];
  if (!record || record.expires < Date.now()) {
    delete resetTokens[token];
    return res.status(400).json({ error: 'Reset link is invalid or has expired.' });
  }

  const users = readUsers();
  if (!users[record.email])
    return res.status(400).json({ error: 'Account not found.' });

  users[record.email].passwordHash = hashPassword(password);
  writeUsers(users);
  delete resetTokens[token];

  res.json({ ok: true, message: 'Password updated. You can now log in.' });
});

// ── Google OAuth ──────────────────────────────────────────────────────────────
app.get('/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.status(501).send('Google OAuth not configured.');
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'consent',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

app.get('/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?auth_error=google_denied');
  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI, grant_type: 'authorization_code',
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const profile = await userInfoRes.json();

    const users = readUsers();
    const key = profile.email.toLowerCase();
    const isNew = !users[key];

    if (isNew) {
      users[key] = {
        name: profile.name || profile.email,
        email: key,
        approved: false,
        provider: 'google',
        registeredAt: Date.now(),
      };
      writeUsers(users);
      sendEmail({
        to: key,
        subject: 'Welcome to EduMitra',
        html: welcomeEmailHtml(profile.name || profile.email),
      });
    }

    req.session.user = { role: 'student', ...publicUser(users[key]) };
    res.redirect('/');
  } catch (err) {
    console.error('[google-oauth]', err.message);
    res.redirect('/?auth_error=google_failed');
  }
});

// ── LinkedIn OAuth ────────────────────────────────────────────────────────────
app.get('/auth/linkedin', (req, res) => {
  if (!LINKEDIN_CLIENT_ID) return res.status(501).send('LinkedIn OAuth not configured.');
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: LINKEDIN_CLIENT_ID,
    redirect_uri: LINKEDIN_REDIRECT_URI,
    scope: 'openid profile email',
  });
  res.redirect(`https://www.linkedin.com/oauth/v2/authorization?${params}`);
});

app.get('/auth/linkedin/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?auth_error=linkedin_denied');
  try {
    const tokenRes = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code, client_id: LINKEDIN_CLIENT_ID, client_secret: LINKEDIN_CLIENT_SECRET,
        redirect_uri: LINKEDIN_REDIRECT_URI,
      }),
    });
    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    const profileRes = await fetch('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const profile = await profileRes.json();

    const email = (profile.email || '').toLowerCase();
    if (!email) throw new Error('LinkedIn did not return an email address.');

    const users = readUsers();
    const isNew = !users[email];

    if (isNew) {
      users[email] = {
        name: profile.name || email,
        email,
        approved: false,
        provider: 'linkedin',
        registeredAt: Date.now(),
      };
      writeUsers(users);
      sendEmail({
        to: email,
        subject: 'Welcome to EduMitra',
        html: welcomeEmailHtml(profile.name || email),
      });
    }

    req.session.user = { role: 'student', ...publicUser(users[email]) };
    res.redirect('/');
  } catch (err) {
    console.error('[linkedin-oauth]', err.message);
    res.redirect('/?auth_error=linkedin_failed');
  }
});

// ── Admin auth ────────────────────────────────────────────────────────────────
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

  const admins = readAdmins();
  const admin = admins[key];
  if (!admin) return res.status(401).json({ error: GENERIC });
  if (!verifyPassword(password || '', admin.passwordHash)) return res.status(401).json({ error: GENERIC });

  req.session.user = { role: 'admin', email: key, name: admin.name };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({ ok: true, user: req.session.user });
});

// ── Admin → students ──────────────────────────────────────────────────────────
app.get('/api/admin/students', requireAdmin, (req, res) => {
  const users = readUsers();
  res.json({ students: Object.values(users).map(publicUser) });
});

app.post('/api/admin/students/:email/approve', requireAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const users = readUsers();
  if (!users[key]) return res.status(404).json({ error: 'User not found.' });
  if (users[key].approved) return res.json({ ok: true, message: 'Already approved.' });

  users[key].approved = true;
  users[key].approvedAt = Date.now();
  writeUsers(users);

  // Send approval email
  sendEmail({
    to: key,
    subject: 'Your EduMitra account is approved',
    html: approvalEmailHtml(users[key].name),
  });

  res.json({ ok: true });
});

app.post('/api/admin/students/:email/reject', requireAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const users = readUsers();
  if (!users[key]) return res.status(404).json({ error: 'User not found.' });
  users[key].approved = false;
  users[key].rejectedAt = Date.now();
  writeUsers(users);
  res.json({ ok: true });
});

app.delete('/api/admin/students/:email', requireAdmin, (req, res) => {
  const key = req.params.email.toLowerCase();
  const users = readUsers();
  if (!users[key]) return res.status(404).json({ error: 'User not found.' });
  delete users[key];
  writeUsers(users);
  res.json({ ok: true });
});

// ── Admin analytics ───────────────────────────────────────────────────────────
app.get('/api/admin/analytics', requireAdmin, (req, res) => {
  const users = readUsers();
  const all = Object.values(users);
  const total = all.length;
  const approved = all.filter(u => u.approved).length;
  const pending = total - approved;

  // Signups per day for the last 14 days
  const now = Date.now();
  const dayMs = 24 * 60 * 60 * 1000;
  const days = Array.from({ length: 14 }, (_, i) => {
    const ts = now - (13 - i) * dayMs;
    const label = new Date(ts).toLocaleDateString('en-IN', { month: 'short', day: 'numeric' });
    return { label, count: 0 };
  });
  all.forEach(u => {
    if (!u.registeredAt) return;
    const age = Math.floor((now - u.registeredAt) / dayMs);
    if (age < 14) days[13 - age].count++;
  });

  res.json({ total, approved, pending, signupsPerDay: days });
});

// ── Superadmin → manage admins ────────────────────────────────────────────────
app.get('/api/superadmin/admins', requireAdmin, (req, res) => {
  if (req.session.user.role !== 'superadmin')
    return res.status(403).json({ error: 'Superadmin only.' });
  const admins = readAdmins();
  res.json({ admins: Object.values(admins).map(({ passwordHash, ...a }) => a) });
});

app.post('/api/superadmin/admins', requireAdmin, (req, res) => {
  if (req.session.user.role !== 'superadmin')
    return res.status(403).json({ error: 'Superadmin only.' });
  const { name, email, password } = req.body || {};
  if (!name || !email || !password)
    return res.status(400).json({ error: 'Name, email and password are required.' });

  const admins = readAdmins();
  const key = email.toLowerCase();
  if (admins[key]) return res.status(409).json({ error: 'Admin already exists.' });

  admins[key] = { name, email: key, passwordHash: hashPassword(password), createdAt: Date.now() };
  writeAdmins(admins);
  res.json({ ok: true });
});

app.delete('/api/superadmin/admins/:email', requireAdmin, (req, res) => {
  if (req.session.user.role !== 'superadmin')
    return res.status(403).json({ error: 'Superadmin only.' });
  const key = req.params.email.toLowerCase();
  if (key === SUPERADMIN_EMAIL)
    return res.status(400).json({ error: 'Cannot delete the superadmin account.' });
  const admins = readAdmins();
  if (!admins[key]) return res.status(404).json({ error: 'Admin not found.' });
  delete admins[key];
  writeAdmins(admins);
  res.json({ ok: true });
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
