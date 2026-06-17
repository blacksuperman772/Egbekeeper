'use strict';
require('dns').setDefaultResultOrder('ipv4first');
require('dotenv').config();

const express      = require('express');
const rateLimit    = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path         = require('path');
const fs           = require('fs');
const crypto       = require('crypto');
const cron         = require('node-cron');
const { createClient } = require('@supabase/supabase-js');

// ── Resend (email) — gracefully disabled if key not set ──────────────────────
let resend = null;
try {
  const { Resend } = require('resend');
  if (process.env.RESEND_API_KEY) resend = new Resend(process.env.RESEND_API_KEY);
} catch (_) {}

const app  = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

// ── Trust proxy (required when behind nginx/Cloudflare) ───────────────────────
// Without this, req.ip is always 127.0.0.1 and rate limiting is useless.
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

// ── CORS — allow only the production origin with credentials ──────────────────
const ALLOWED_ORIGIN = process.env.APP_URL || 'http://localhost:3000';
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin === ALLOWED_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});

// ── Supabase admin client (service role — server-side only) ──────────────────
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL        || '',
  process.env.SUPABASE_SERVICE_ROLE_KEY || '',
  { auth: { persistSession: false } }
);

// ── Remove fingerprinting ─────────────────────────────────────────────────────
app.disable('x-powered-by');

// ── Security headers ─────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      // Inline scripts used throughout; migrate to nonces in a future pass
      "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net https://js.paystack.co",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      // Proxy reach: our own API, Supabase, OpenAI (via our proxy only)
      // ElevenLabs SDK: HTTPS for auth + WSS for streaming; livekit-client uses wss://livekit.rtc.elevenlabs.io for WebRTC transport
      "connect-src 'self' https://*.supabase.co wss://*.supabase.co https://api.openai.com https://api.paystack.co https://api.elevenlabs.io wss://api.elevenlabs.io wss://livekit.rtc.elevenlabs.io https://livekit.rtc.elevenlabs.io",
      "img-src 'self' data:",
      "frame-ancestors 'none'",
    ].join('; ')
  );
  next();
});

// ── Block sensitive files ─────────────────────────────────────────────────────
const BLOCKED = [
  '/server.js', '/.env', '/package.json', '/package-lock.json',
  '/node_modules', '/.gitignore', '/supabase', '/generate-assets.js',
];
app.use((req, res, next) => {
  const p = req.path.toLowerCase();
  if (BLOCKED.some(b => p === b || p.startsWith('/node_modules') || p.startsWith('/supabase'))) {
    return res.status(404).end();
  }
  next();
});

// ── Body + cookie parsing ─────────────────────────────────────────────────────
app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());

// ── Supabase credential injection ─────────────────────────────────────────────
// Replaces placeholder tokens in HTML before serving.
// The anon key is safe to expose to browsers by design, but we route it
// through server injection so credentials never live in source-controlled HTML.
function injectSupabaseConfig(html) {
  return html
    .replace(/window\.__EK_SUPABASE_URL__/g,  JSON.stringify(process.env.SUPABASE_URL       || ''))
    .replace(/window\.__EK_SUPABASE_ANON__/g, JSON.stringify(process.env.SUPABASE_ANON_KEY  || ''));
}

function serveInjectedHtml(filePath) {
  return (req, res) => {
    try {
      const raw  = fs.readFileSync(filePath, 'utf8');
      const html = injectSupabaseConfig(raw);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.send(html);
    } catch (err) {
      console.error('serveInjectedHtml error:', err.message);
      res.status(500).send('Internal server error');
    }
  };
}

// ── JWT verification middleware ───────────────────────────────────────────────
// Reads the ek_session cookie, verifies with Supabase, attaches user to req.
async function verifySession(req, res, next) {
  const token = req.cookies?.ek_session;
  if (!token) return next(); // unauthenticated — route handlers decide what to do

  try {
    const { data, error } = await supabaseAdmin.auth.getUser(token);
    if (!error && data?.user) {
      req.user       = data.user;
      req.authToken  = token;
    }
  } catch (_) {
    // Treat any verification failure as unauthenticated
  }
  next();
}

// ── Auth-required guard (HTML pages) — redirects to /auth.html ───────────────
function requireAuthPage(req, res, next) {
  if (req.user) return next();
  res.redirect('/auth.html');
}

// ── Auth-required guard (API routes) — returns 401 JSON ──────────────────────
function requireAuthApi(req, res, next) {
  if (req.user) return next();
  res.status(401).json({ error: 'Authentication required' });
}

// Apply session verification globally (non-blocking — just attaches user)
app.use(verifySession);

// ── Rate limiting ─────────────────────────────────────────────────────────────
const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests.' },
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many admin requests.' },
});

// Strict limiter for sensitive token endpoints (5/min)
const tokenLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many token requests. Please wait.' },
});

// ── Onboarding guard — already-onboarded users go straight to workspace ───────
async function requireIncompleteOnboarding(req, res, next) {
  if (!req.user) return next();
  try {
    const { data } = await supabaseAdmin
      .from('user_profiles')
      .select('onboarding_complete')
      .eq('id', req.user.id)
      .single();
    if (data?.onboarding_complete) return res.redirect('/workspace.html');
  } catch (_) { /* profile missing — let them through to onboarding */ }
  next();
}

// ── Admin middleware — uses is_admin boolean from DB, fails closed ────────────
async function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Authentication required' });
  try {
    const { data: profile } = await supabaseAdmin
      .from('user_profiles')
      .select('is_admin')
      .eq('id', req.user.id)
      .maybeSingle();
    if (!profile?.is_admin) return res.status(403).json({ error: 'Forbidden' });
    next();
  } catch (_) {
    return res.status(503).json({ error: 'Could not verify admin status' });
  }
}

// ── Auth session endpoints (HttpOnly cookie management) ───────────────────────
// VULN-01 fix: cookies are set server-side so they can be HttpOnly.
// The client POSTs the Supabase access token here after sign-in; the server
// verifies it, then writes the HttpOnly cookie so JS can never read it.
app.post('/api/auth/session', tokenLimiter, async (req, res) => {
  const { access_token } = req.body || {};
  if (!access_token || typeof access_token !== 'string' || access_token.length > 4096) {
    return res.status(400).json({ error: 'Invalid token' });
  }
  try {
    const { data, error } = await supabaseAdmin.auth.getUser(access_token);
    if (error || !data?.user) return res.status(401).json({ error: 'Invalid or expired token' });
    res.cookie('ek_session', access_token, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000,
      path:     '/',
    });
    res.json({ ok: true });
  } catch (_) {
    res.status(500).json({ error: 'Session error' });
  }
});

// DELETE /api/auth/session — sign out (clears the HttpOnly cookie)
app.delete('/api/auth/session', (req, res) => {
  res.clearCookie('ek_session', { path: '/', sameSite: 'strict', httpOnly: true });
  res.json({ ok: true });
});

// GET /api/auth/status — lightweight auth check for pages that cannot read HttpOnly cookies
// (e.g. pricing.html checkout flow). No sensitive data is returned.
app.get('/api/auth/status', (req, res) => {
  res.json({ authenticated: !!req.user });
});

// ── Root redirect ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.redirect('/edgekeeper.html'));

// ── Public HTML pages (no auth required) ─────────────────────────────────────
app.get('/edgekeeper.html', serveInjectedHtml(path.join(__dirname, 'edgekeeper.html')));

// Auth page — redirect already-authenticated users straight to workspace.
// Without this, a logged-in user hitting /auth.html would see the form
// briefly before client-side JS redirected them, which also risks running
// the billing initiation logic a second time.
app.get('/auth.html', (req, res, next) => {
  if (req.user) return res.redirect('/workspace.html');
  next();
}, serveInjectedHtml(path.join(__dirname, 'auth.html')));

app.get('/reset-password.html', serveInjectedHtml(path.join(__dirname, 'reset-password.html')));
app.get('/privacy.html',  (req, res) => res.sendFile(path.join(__dirname, 'privacy.html')));
app.get('/terms.html',    (req, res) => res.sendFile(path.join(__dirname, 'terms.html')));
app.get('/404.html',      (req, res) => res.status(404).sendFile(path.join(__dirname, '404.html')));
app.get('/robots.txt',    (req, res) => res.type('text/plain').sendFile(path.join(__dirname, 'robots.txt')));
app.get('/sitemap.xml',   (req, res) => res.type('application/xml').sendFile(path.join(__dirname, 'sitemap.xml')));
// ── Mentor + Method pages (public) ───────────────────────────────────────────
app.get('/mike',    (req, res) => res.sendFile(path.join(__dirname, 'mike.html')));
app.get('/ashley',  (req, res) => res.sendFile(path.join(__dirname, 'ashley.html')));
app.get('/method',  (req, res) => res.sendFile(path.join(__dirname, 'method.html')));

app.get('/pricing.html',    (req, res) => {
  const f = path.join(__dirname, 'pricing.html');
  if (fs.existsSync(f)) {
    res.setHeader('Cache-Control', 'no-cache');
    res.sendFile(f);
  } else {
    res.redirect('/edgekeeper.html#pricing');
  }
});

// ── Protected HTML pages (auth required) ─────────────────────────────────────
// Onboarding is now pre-auth — new users arrive here before creating an account.
// requireIncompleteOnboarding still redirects authenticated users who already
// completed onboarding straight to /workspace.html.
app.get('/onboarding.html', requireIncompleteOnboarding, serveInjectedHtml(path.join(__dirname, 'onboarding.html')));

// ── Onboarding registration — creates account at the END of intake ────────────
// Called from onboarding.html after the intake completes. No auth required.
app.post('/api/onboarding/register', apiLimiter, async (req, res) => {
  const { email, password, mentor, plan, guardianLevel, privateNotes, northStar, livingId } = req.body || {};

  if (!email || typeof email !== 'string' || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ error: 'A valid email address is required.' });
  }
  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  const safePlan = ['free', 'starter', 'pro', 'institutional'].includes(plan) ? plan : 'free';
  const safeMentor = ['mike', 'ashley'].includes(mentor) ? mentor : 'mike';

  // Create the user. email_confirm: true skips the confirmation email so the
  // user can sign straight in — change to false if you want email verification.
  const { data: userData, error: createErr } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    user_metadata: { mentor: safeMentor, requested_plan: safePlan },
    email_confirm: true,
  });

  if (createErr) {
    const msg = createErr.message.toLowerCase();
    if (msg.includes('already registered') || msg.includes('already exists')) {
      return res.status(409).json({ error: 'An account with that email already exists. Please sign in.' });
    }
    console.error('Onboarding register error:', createErr.message);
    return res.status(400).json({ error: createErr.message });
  }

  // Create user_profiles row with onboarding data.
  // The trigger (migration 005) may have already created a bare row — upsert handles both cases.
  await supabaseAdmin.from('user_profiles').upsert({
    id:                  userData.user.id,
    mentor:              safeMentor,
    guardian_level:      guardianLevel || 'warn',
    onboarding_complete: true,
    subscription_status: safePlan,
    private_notes:       (privateNotes || '').slice(0, 4000),
    north_star:          (northStar    || '').slice(0, 500),
    living_identity:     (livingId     || '').slice(0, 500),
  }, { onConflict: 'id' });

  res.json({ success: true, user_id: userData.user.id, plan: safePlan });
});
app.get('/workspace.html',   requireAuthPage, serveInjectedHtml(path.join(__dirname, 'workspace.html')));
app.get('/settings.html',    requireAuthPage, serveInjectedHtml(path.join(__dirname, 'settings.html')));
app.get('/assessment.html',  requireAuthPage, serveInjectedHtml(path.join(__dirname, 'assessment.html')));

// ── Admin dashboard (admin only) ──────────────────────────────────────────────
app.get('/admin.html', requireAuthPage, (req, res, next) => {
  const adminEmail = process.env.ADMIN_EMAIL || 'alexandermwhitmore@gmail.com';
  if (req.user.email !== adminEmail) return res.redirect('/workspace.html');
  next();
}, serveInjectedHtml(path.join(__dirname, 'admin.html')));

// ── Internal office (admin only) ─────────────────────────────────────────────
app.get('/office.html', requireAuthPage, (req, res, next) => {
  const adminEmail = process.env.ADMIN_EMAIL || 'alexandermwhitmore@gmail.com';
  if (req.user.email !== adminEmail) return res.redirect('/workspace.html');
  next();
}, serveInjectedHtml(path.join(__dirname, 'office.html')));

// ── Static files (JS, CSS, images, etc.) ─────────────────────────────────────
// HTML files handled above via explicit routes; block direct .html fallthrough
app.use(express.static(path.join(__dirname), {
  dotfiles: 'ignore', // never serve .env, .gitignore, etc.
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      // Should not be reached — explicit routes handle HTML — just in case
      res.setHeader('Cache-Control', 'no-cache');
    }
  },
  // Don't serve .html through static; let explicit routes above handle them
  extensions: [],
}));

// ────────────────────────────────────────────────────────────────────────────
// API ROUTES
// ────────────────────────────────────────────────────────────────────────────

// ── Chat proxy (requires auth) ────────────────────────────────────────────────
app.post('/api/chat', requireAuthApi, chatLimiter, async (req, res) => {
  const { messages, systemPrompt, mentor = 'mike', is_opener = false } = req.body;

  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'messages must be a non-empty array' });
  }
  if (messages.length > 35) {
    return res.status(400).json({ error: 'Too many messages in context' });
  }
  if (typeof systemPrompt !== 'string') {
    return res.status(400).json({ error: 'systemPrompt must be a string' });
  }
  if (systemPrompt.length > 16000) {
    return res.status(400).json({ error: 'systemPrompt too long' });
  }
  if (!['mike', 'ashley'].includes(mentor)) {
    return res.status(400).json({ error: 'Invalid mentor' });
  }

  for (const msg of messages) {
    if (!msg || typeof msg.role !== 'string' || typeof msg.content !== 'string') {
      return res.status(400).json({ error: 'Invalid message format' });
    }
    if (!['user', 'assistant', 'system'].includes(msg.role)) {
      return res.status(400).json({ error: 'Invalid message role' });
    }
    if (msg.content.length > 4000) {
      return res.status(400).json({ error: 'Message content too long' });
    }
  }

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey || apiKey === 'your-openai-key-here') {
    console.error('OPENAI_API_KEY not configured');
    return res.status(503).json({ error: 'AI service not configured' });
  }

  // ── Message usage enforcement ───────────────────────────────────────────────
  // Session openers ([Session start] / __first_session__) do not count against
  // the user's message quota — they are infrastructure, not conversation turns.
  const lastMsg = messages[messages.length - 1];
  const isSystemOpener = is_opener === true ||
    (lastMsg?.role === 'user' && ['[Session start]', '__first_session__'].includes(lastMsg?.content));

  try {
    const { data: profile } = await supabaseAdmin
      .from('user_profiles')
      .select('bypass_subscription, subscription_status')
      .eq('id', req.user.id)
      .single();

    if (!profile?.bypass_subscription && !isSystemOpener) {
      const monthKey = new Date().toISOString().slice(0, 7); // 'YYYY-MM'
      const { data: usage, error: usageErr } = await supabaseAdmin
        .rpc('increment_message_usage', {
          p_user_id: req.user.id,
          p_mentor:  mentor,
          p_month:   monthKey,
        });

      if (usageErr) {
        console.error('Usage RPC error:', usageErr.message);
      } else if (usage?.[0]?.limit_reached) {
        const plan = profile?.subscription_status || 'free';
        const nextPlan = plan === 'free' ? 'Resident' : plan === 'starter' ? 'Fellow' : 'Private Office';
        return res.status(429).json({
          error: 'Message limit reached for this month.',
          plan,
          upgrade_to: nextPlan,
          usage_count: usage[0].new_count,
        });
      } else if (usage?.[0]?.near_limit) {
        // Grace buffer — attach a warning header; the response still goes through
        res.setHeader('X-Usage-Warning', 'near_limit');
      }
    }
  } catch (usageCheckErr) {
    // Non-fatal — don't block the chat on a usage tracking failure
    console.error('Usage check failed:', usageCheckErr.message);
  }

  try {
    const upstream = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          ...messages,
        ],
        max_completion_tokens: 700,
      }),
    });

    if (!upstream.ok) {
      const err = await upstream.json().catch(() => ({}));
      console.error('OpenAI error:', upstream.status, err);
      return res.status(502).json({ error: 'AI service error' });
    }

    const data    = await upstream.json();
    const content = (data.choices?.[0]?.message?.content || '').trim();
    res.json({ content });

  } catch (err) {
    console.error('Chat proxy error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Notebook sync ─────────────────────────────────────────────────────────────
app.get('/api/notebook/:mentor', requireAuthApi, apiLimiter, async (req, res) => {
  const { mentor } = req.params;
  if (!['mike', 'ashley'].includes(mentor)) {
    return res.status(400).json({ error: 'Invalid mentor' });
  }

  const { data, error } = await supabaseAdmin
    .from('notebooks')
    .select('*')
    .eq('user_id', req.user.id)
    .eq('mentor', mentor)
    .maybeSingle();

  if (error) {
    console.error('Notebook GET error:', error.message);
    return res.status(500).json({ error: 'Database error' });
  }

  res.json({ notebook: data || null });
});

app.post('/api/notebook/:mentor', requireAuthApi, apiLimiter, async (req, res) => {
  const { mentor } = req.params;
  if (!['mike', 'ashley'].includes(mentor)) {
    return res.status(400).json({ error: 'Invalid mentor' });
  }

  const allowed = [
    'session_count', 'trust_level', 'current_theory', 'theory_history',
    'facts', 'theories', 'open_questions', 'uncertainties', 'observations',
    'patterns', 'emotional_map', 'strengths', 'concerns', 'breakthroughs',
    'commitments', 'story_moments', 'conversation_history',
  ];

  // Only pass whitelisted fields to prevent privilege escalation
  const payload = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) payload[k] = req.body[k];
  }

  for (const k of Object.keys(payload)) {
    if (typeof payload[k] === 'string' && payload[k].length > 50000) {
      return res.status(400).json({ error: `Field ${k} exceeds maximum length` });
    }
  }

  const { data, error } = await supabaseAdmin
    .from('notebooks')
    .upsert(
      { user_id: req.user.id, mentor, ...payload },
      { onConflict: 'user_id,mentor' }
    )
    .select()
    .single();

  if (error) {
    console.error('Notebook POST error:', error.message);
    return res.status(500).json({ error: 'Database error' });
  }

  res.json({ notebook: data });
});

// ── User profile (intake data for client hydration) ──────────────────────────
app.get('/api/profile', requireAuthApi, apiLimiter, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('user_profiles')
    .select('mentor, private_notes, north_star, living_identity, guardian_level, subscription_status, trader_stage, current_identity, target_identity, readiness_score, assessment_complete')
    .eq('id', req.user.id)
    .maybeSingle();

  if (error) return res.status(500).json({ error: 'Database error' });
  if (!data)  return res.json({ profile: null });

  res.json({
    profile: {
      id:                  req.user.id,
      member_since:        req.user.created_at        || null,
      mentor:              data.mentor                || null,
      private_notes:       data.private_notes         || null,
      north_star:          data.north_star            || null,
      living_identity:     data.living_identity       || null,
      guardian_level:      data.guardian_level        || 'warn',
      plan:                data.subscription_status   || 'free',
      trader_stage:        data.trader_stage          || 'explorer',
      current_identity:    data.current_identity      || null,
      target_identity:     data.target_identity       || null,
      readiness_score:     data.readiness_score       ?? 0,
      assessment_complete: data.assessment_complete   || false,
    },
  });
});

// ── Message usage stats ───────────────────────────────────────────────────────
app.get('/api/usage', requireAuthApi, apiLimiter, async (req, res) => {
  const monthKey = new Date().toISOString().slice(0, 7);

  const [profileRes, usageRes] = await Promise.all([
    // maybeSingle() returns { data: null, error: null } when no row exists,
    // whereas .single() returns an error with code PGRST116 — which was
    // causing a spurious 500 for new users whose profile row hadn't been
    // created yet (e.g. right after sign-up, before onboarding completes).
    supabaseAdmin
      .from('user_profiles')
      .select('subscription_status, bypass_subscription')
      .eq('id', req.user.id)
      .maybeSingle(),
    supabaseAdmin
      .from('message_usage')
      .select('mentor, message_count')
      .eq('user_id', req.user.id)
      .eq('month_key', monthKey),
  ]);

  // A real database error (not just a missing row) should still surface as 500.
  if (profileRes.error) return res.status(500).json({ error: 'Database error' });

  const plan      = profileRes.data?.subscription_status || 'free';
  const bypass    = profileRes.data?.bypass_subscription || false;
  const limits    = { free: 7, starter: 500, pro: 2000, institutional: null };
  const limit     = bypass ? null : (limits[plan] ?? 50);

  const usage = {};
  for (const row of (usageRes.data || [])) {
    usage[row.mentor] = row.message_count;
  }
  const totalUsed = Object.values(usage).reduce((a, b) => a + b, 0);

  res.json({ plan, bypass, limit, used: totalUsed, by_mentor: usage, month: monthKey });
});

// ── Journal entries ───────────────────────────────────────────────────────────
app.get('/api/journal', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: jGetProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const jGetPlan   = jGetProfile?.subscription_status || 'free';
  const jGetBypass = jGetProfile?.bypass_subscription || false;
  if (!jGetBypass && !['starter', 'pro', 'institutional'].includes(jGetPlan)) {
    return res.status(403).json({ error: 'Journal access requires the Resident plan or higher.' });
  }
  const limit  = Math.min(parseInt(req.query.limit  || '50', 10), 100);
  const offset = Math.max(parseInt(req.query.offset || '0',  10), 0);

  // VULN-21: explicit column list — never expose internal fields added in the future
  const { data, error, count } = await supabaseAdmin
    .from('journal_entries')
    .select('id, user_id, content, entry_type, trade_data, mentor_notes, created_at', { count: 'exact' })
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);

  if (error) {
    console.error('Journal GET error:', error.message);
    return res.status(500).json({ error: 'Database error' });
  }

  res.json({ entries: data, total: count });
});

app.post('/api/journal', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: jPostProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const jPostPlan   = jPostProfile?.subscription_status || 'free';
  const jPostBypass = jPostProfile?.bypass_subscription || false;
  if (!jPostBypass && !['starter', 'pro', 'institutional'].includes(jPostPlan)) {
    return res.status(403).json({ error: 'Journal access requires the Resident plan or higher.' });
  }
  const { content, entry_type, trade_data, mentor_notes } = req.body;

  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'content is required' });
  }
  if (content.length > 20000) {
    return res.status(400).json({ error: 'content too long' });
  }

  const validTypes = ['free', 'pre_trade', 'post_trade', 'weekly', 'monthly'];
  const type = validTypes.includes(entry_type) ? entry_type : 'free';

  // VULN-14: size-limit trade_data and mentor_notes
  if (trade_data !== undefined && trade_data !== null) {
    const tdStr = typeof trade_data === 'string' ? trade_data : JSON.stringify(trade_data);
    if (tdStr.length > 10000) return res.status(400).json({ error: 'trade_data too large' });
  }
  if (mentor_notes !== undefined && mentor_notes !== null) {
    if (typeof mentor_notes !== 'string' || mentor_notes.length > 5000) {
      return res.status(400).json({ error: 'mentor_notes must be a string under 5000 characters' });
    }
  }

  const { data, error } = await supabaseAdmin
    .from('journal_entries')
    .insert({
      user_id:      req.user.id,
      content:      content.trim(),
      entry_type:   type,
      trade_data:   trade_data   || null,
      mentor_notes: mentor_notes || null,
    })
    .select()
    .single();

  if (error) {
    console.error('Journal POST error:', error.message);
    return res.status(500).json({ error: 'Database error' });
  }

  res.status(201).json({ entry: data });

  // Async rules check — fire and forget; does not block the response
  checkJournalAgainstRules(req.user.id, data.id, content.trim()).catch(err =>
    console.error('Rules check error:', err.message)
  );
});

// ── Journal AI Rules Processor ────────────────────────────────────────────────
// Called after every journal save. Checks the entry against the user's active
// trading rules using GPT. Stores violations in rule_violations, updates status.
async function checkJournalAgainstRules(userId, entryId, content) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return;

  // Fetch user's active rules
  const { data: rules } = await supabaseAdmin
    .from('trading_rules')
    .select('id, rule_text, category')
    .eq('user_id', userId)
    .eq('is_active', true)
    .limit(30);

  if (!rules || rules.length === 0) {
    await supabaseAdmin.from('journal_entries')
      .update({ ai_check_status: 'skipped' })
      .eq('id', entryId);
    return;
  }

  // Mark as processing
  await supabaseAdmin.from('journal_entries')
    .update({ ai_check_status: 'processing' })
    .eq('id', entryId);

  const rulesList = rules.map((r, i) => `${i + 1}. [${r.id}] (${r.category}) ${r.rule_text}`).join('\n');
  const systemPrompt = `You are a trading discipline analyst. A trader has written a journal entry.
Check if it describes behaviour that violates any of their personal trading rules.
Respond ONLY with valid JSON — no prose, no markdown fences.
Format: { "violations": [ { "rule_id": "<uuid>", "confidence": 0.0-1.0, "mentor_note": "1-2 sentence explanation in mentor voice", "evidence_quote": "exact quote from journal that triggered this" } ] }
If no violations, return { "violations": [] }.
Never hallucinate rule IDs — only use IDs from the list provided.`;

  const userMsg = `Trading Rules:\n${rulesList}\n\nJournal Entry:\n${content.slice(0, 3000)}`;

  try {
    const upstream = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userMsg },
        ],
        max_completion_tokens: 600,
        response_format: { type: 'json_object' },
      }),
    });

    const gptData = await upstream.json();
    const raw = gptData.choices?.[0]?.message?.content || '{}';
    let parsed;
    try { parsed = JSON.parse(raw); } catch (_) { parsed = { violations: [] }; }

    const violations = Array.isArray(parsed.violations) ? parsed.violations : [];

    // Validate that referenced rule IDs actually belong to this user
    const validRuleIds = new Set(rules.map(r => r.id));
    const safeViolations = violations.filter(v =>
      v.rule_id && validRuleIds.has(v.rule_id) &&
      typeof v.mentor_note === 'string' && v.mentor_note.length >= 10
    );

    if (safeViolations.length > 0) {
      await supabaseAdmin.from('rule_violations').insert(
        safeViolations.map(v => ({
          user_id:          userId,
          journal_entry_id: entryId,
          rule_id:          v.rule_id,
          confidence:       Math.min(1, Math.max(0, Number(v.confidence) || 1)),
          mentor_note:      String(v.mentor_note).slice(0, 600),
          evidence_quote:   v.evidence_quote ? String(v.evidence_quote).slice(0, 500) : null,
        }))
      );
    }

    await supabaseAdmin.from('journal_entries')
      .update({ ai_check_status: 'done', ai_analysis_raw: parsed })
      .eq('id', entryId);

  } catch (err) {
    console.error('Journal rules GPT error:', err.message);
    // Reset to pending so it can be retried
    await supabaseAdmin.from('journal_entries')
      .update({ ai_check_status: 'pending' })
      .eq('id', entryId);
  }
}

// ── Voice session — ElevenLabs signed URL proxy ───────────────────────────────
// Returns a signed WebSocket URL so the browser SDK can connect directly to
// ElevenLabs. Audio never transits our server; only the token exchange does.
// Signed URLs are single-use and short-lived — intentionally never cached.
app.post('/api/voice/session', requireAuthApi, apiLimiter, async (req, res) => {
  // Enforce plan gate server-side — the client-side check in handleVoiceNavClick()
  // is cosmetic only and can be bypassed by direct POST requests.
  let plan;
  try {
    const { data: profile } = await supabaseAdmin
      .from('user_profiles')
      .select('subscription_status, bypass_subscription')
      .eq('id', req.user.id)
      .maybeSingle();

    plan = profile?.subscription_status || 'free';
    const bypass = profile?.bypass_subscription || false;

    if (!bypass) {
      const monthKey = new Date().toISOString().slice(0, 7);
      const { data: voiceData, error: voiceErr } = await supabaseAdmin
        .rpc('increment_voice_usage', { p_user_id: req.user.id, p_month: monthKey });

      if (voiceErr) {
        console.error('Voice usage RPC error:', voiceErr.message);
        return res.status(500).json({ error: 'Could not verify voice usage. Please try again.' });
      }

      const row = voiceData?.[0];
      if (row?.limit_reached) {
        const VOICE_LIMITS = { free: 1, starter: 3, pro: 8, institutional: 999 };
        const limit = VOICE_LIMITS[plan] ?? 1;
        return res.status(429).json({
          error: `You've used all ${limit} voice session${limit === 1 ? '' : 's'} for this month.`,
          plan,
          upgrade_to: plan === 'free' ? 'starter' : plan === 'starter' ? 'pro' : null,
        });
      }
    }
  } catch (planCheckErr) {
    console.error('Voice plan check error:', planCheckErr.message);
    return res.status(500).json({ error: 'Could not verify plan. Please try again.' });
  }

  const mentor = req.body?.mentor;
  if (!['mike', 'ashley'].includes(mentor)) {
    return res.status(400).json({ error: 'Invalid mentor' });
  }

  const apiKey  = process.env.ELEVENLABS_API_KEY;
  const agentId = mentor === 'ashley'
    ? process.env.ELEVENLABS_ASHLEY_AGENT_ID
    : process.env.ELEVENLABS_MIKE_AGENT_ID;

  if (!apiKey || !agentId) {
    return res.status(501).json({ error: 'Voice sessions not yet configured' });
  }

  // Abort if ElevenLabs does not respond within 8 seconds
  const controller = new AbortController();
  const timeout    = setTimeout(() => controller.abort(), 8000);

  try {
    const upstream = await fetch(
      `https://api.elevenlabs.io/v1/convai/conversations/get_signed_url?agent_id=${encodeURIComponent(agentId)}`,
      { headers: { 'xi-api-key': apiKey }, signal: controller.signal }
    );
    clearTimeout(timeout);

    if (!upstream.ok) {
      const errBody = await upstream.json().catch(() => ({}));
      console.error('ElevenLabs error:', upstream.status, errBody);
      if (upstream.status === 401 || upstream.status === 403) {
        return res.status(502).json({ error: 'Voice service authentication failed. Contact support.' });
      }
      if (upstream.status >= 500) {
        return res.status(502).json({ error: 'Voice service is temporarily unavailable. Please try again in a moment.' });
      }
      return res.status(502).json({ error: 'Voice service error' });
    }

    const data = await upstream.json();
    if (!data.signed_url) {
      console.error('ElevenLabs returned no signed_url:', data);
      return res.status(502).json({ error: 'Voice service returned an unexpected response.' });
    }

    res.json({ signedUrl: data.signed_url });
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'AbortError') {
      console.error('Voice session proxy: ElevenLabs request timed out');
      return res.status(502).json({ error: 'Voice service timed out. Please try again.' });
    }
    console.error('Voice session proxy error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Guardian Layer ────────────────────────────────────────────────────────────

// Calculate lock level from account state
function calcLockLevel(data) {
  const losses = data.consecutive_losses || 0;
  const pnlPct = data.daily_pnl_pct || 0;
  const drawdown = data.max_drawdown_pct || 0;
  if (losses >= 5 || pnlPct <= -5 || drawdown >= 5)  return 5;
  if (losses >= 4 || pnlPct <= -3 || drawdown >= 4)  return 4;
  if (losses >= 3 || pnlPct <= -2 || drawdown >= 3)  return 3;
  if (losses >= 2 || pnlPct <= -1 || drawdown >= 2)  return 2;
  return 1;
}

// GET /api/guardian — current account state (Resident+ only)
app.get('/api/guardian', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const plan   = profile?.subscription_status || 'free';
  const bypass = profile?.bypass_subscription || false;
  if (!bypass && !['starter', 'pro', 'institutional'].includes(plan)) {
    return res.status(403).json({ error: 'Guardian Layer requires the Resident plan or higher.' });
  }
  const { data, error } = await supabaseAdmin
    .from('guardian_data')
    .select('*')
    .eq('user_id', req.user.id)
    .maybeSingle();

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ guardian: data || null });
});

// POST /api/guardian/update — upsert account data (manual entry or EA webhook)
// Accepts session cookie auth OR Bearer token (stored as guardian_webhook_token in profile)
app.post('/api/guardian/update', apiLimiter, async (req, res) => {
  let userId = null;

  // Primary: session cookie auth
  if (req.user) {
    userId = req.user.id;
  } else {
    // Secondary: Bearer token (EA webhook integration) — VULN-04/12 fix
    const authHeader = req.headers.authorization || '';
    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
    const token = bearerMatch ? bearerMatch[1].trim() : '';
    if (token) {
      const { data: profile } = await supabaseAdmin
        .from('user_profiles')
        .select('id')
        .eq('guardian_webhook_token', token)
        .maybeSingle();
      if (profile) userId = profile.id;
    }
  }

  if (!userId) return res.status(401).json({ error: 'Authentication required' });

  // Enforce plan gate — Guardian is Resident+ only
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', userId)
    .maybeSingle();

  const plan   = profile?.subscription_status || 'free';
  const bypass = profile?.bypass_subscription || false;
  if (!bypass && !['starter', 'pro', 'institutional'].includes(plan)) {
    return res.status(403).json({ error: 'Guardian Layer requires the Resident plan or higher.' });
  }

  const {
    balance, equity, daily_pnl, daily_pnl_pct,
    consecutive_losses, open_lots, max_drawdown_pct, platform,
  } = req.body;

  // VULN-13: numeric range validation
  function inRange(v, lo, hi) { return v === undefined || v === null || (typeof v === 'number' && isFinite(v) && v >= lo && v <= hi); }
  if (!inRange(balance, 0, 10_000_000))            return res.status(400).json({ error: 'balance out of range' });
  if (!inRange(equity, 0, 10_000_000))             return res.status(400).json({ error: 'equity out of range' });
  if (!inRange(daily_pnl, -1_000_000, 1_000_000)) return res.status(400).json({ error: 'daily_pnl out of range' });
  if (!inRange(daily_pnl_pct, -100, 100))          return res.status(400).json({ error: 'daily_pnl_pct out of range' });
  if (!inRange(consecutive_losses, 0, 100))        return res.status(400).json({ error: 'consecutive_losses out of range' });
  if (!inRange(open_lots, 0, 10_000))              return res.status(400).json({ error: 'open_lots out of range' });
  if (!inRange(max_drawdown_pct, 0, 100))          return res.status(400).json({ error: 'max_drawdown_pct out of range' });
  if (platform !== undefined && (typeof platform !== 'string' || !['mt4','mt5','ctrader','tradingview','manual'].includes(platform))) {
    return res.status(400).json({ error: 'invalid platform value' });
  }

  const lockLevel = calcLockLevel({ consecutive_losses, daily_pnl_pct, max_drawdown_pct });

  const { data: upserted, error: upsertErr } = await supabaseAdmin
    .from('guardian_data')
    .upsert({
      user_id:            userId,
      balance:            balance            ?? null,
      equity:             equity             ?? null,
      daily_pnl:          daily_pnl          ?? null,
      daily_pnl_pct:      daily_pnl_pct      ?? null,
      consecutive_losses: consecutive_losses ?? 0,
      open_lots:          open_lots          ?? 0,
      max_drawdown_pct:   max_drawdown_pct   ?? 0,
      platform:           platform           || 'manual',
      lock_level:         lockLevel,
      is_connected:       true,
      last_updated:       new Date().toISOString(),
    }, { onConflict: 'user_id' })
    .select()
    .single();

  if (upsertErr) return res.status(500).json({ error: 'Database error' });
  res.json({ guardian: upserted, lock_level: lockLevel });
});

// GET /api/guardian/token — return (or generate) the user's webhook token (Resident+)
app.get('/api/guardian/token', requireAuthApi, tokenLimiter, async (req, res) => {
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('guardian_webhook_token, subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const plan   = profile?.subscription_status || 'free';
  const bypass = profile?.bypass_subscription || false;
  if (!bypass && !['starter', 'pro', 'institutional'].includes(plan)) {
    return res.status(403).json({ error: 'Guardian Layer requires the Resident plan or higher.' });
  }

  let token = profile?.guardian_webhook_token;
  if (!token) {
    // Generate a new 32-byte hex token
    token = require('crypto').randomBytes(32).toString('hex');
    await supabaseAdmin
      .from('user_profiles')
      .update({ guardian_webhook_token: token })
      .eq('id', req.user.id);
  }
  res.json({ token });
});

// GET /api/guardian/ea/:platform — download a pre-configured EA file with token embedded (Resident+)
app.get('/api/guardian/ea/:platform', requireAuthApi, apiLimiter, async (req, res) => {
  const { platform } = req.params;
  if (!['mt4', 'mt5'].includes(platform)) {
    return res.status(400).json({ error: 'platform must be mt4 or mt5' });
  }

  // Ensure the user has (or gets) a webhook token
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('guardian_webhook_token, subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const eaPlan   = profile?.subscription_status || 'free';
  const eaBypass = profile?.bypass_subscription || false;
  if (!eaBypass && !['starter', 'pro', 'institutional'].includes(eaPlan)) {
    return res.status(403).json({ error: 'Guardian Layer requires the Resident plan or higher.' });
  }

  let token = profile?.guardian_webhook_token;
  if (!token) {
    const crypto = require('crypto');
    token = crypto.randomBytes(32).toString('hex');
    await supabaseAdmin
      .from('user_profiles')
      .update({ guardian_webhook_token: token })
      .eq('id', req.user.id);
  }

  const webhookUrl = `${req.protocol}://${req.get('host')}/api/guardian/update`;
  const ext = platform === 'mt4' ? 'mq4' : 'mq5';
  const eaCode = platform === 'mt4'
    ? buildMT4EA(token, webhookUrl)
    : buildMT5EA(token, webhookUrl);

  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="EdgeKeeper_Guardian.${ext}"`);
  res.send(eaCode);
});

function buildMT4EA(token, webhookUrl) {
  return `//+------------------------------------------------------------------+
//|  EdgeKeeper Guardian Layer — MT4 Expert Advisor                  |
//|  Sends live account state to EdgeKeeper every 60 seconds.        |
//|  Setup: Attach to any chart. Tools > Options > Expert Advisors   |
//|         enable "Allow WebRequest for listed URL":                 |
//|         ${webhookUrl.replace('/api/guardian/update', '')}
//+------------------------------------------------------------------+
#property copyright "EdgeKeeper"
#property version   "1.0"
#property strict

// ── Configuration (pre-filled — do not share this file) ────────────
input string WebhookURL  = "${webhookUrl}";
input string BearerToken = "${token}";
input int    IntervalSec = 60;   // How often to send data (seconds)

// ── State tracking ──────────────────────────────────────────────────
datetime lastSent    = 0;
double   dayOpenBalance = 0;
int      consecLosses   = 0;
double   peakBalance    = 0;
int      lastTradeCount = 0;
bool     initialized    = false;

//+------------------------------------------------------------------+
int OnInit() {
  dayOpenBalance = AccountBalance();
  peakBalance    = AccountBalance();
  EventSetTimer(IntervalSec);
  SendAccountData();
  return INIT_SUCCEEDED;
}

void OnDeinit(const int reason) { EventKillTimer(); }

void OnTimer() { SendAccountData(); }

void OnTrade() {
  // Recalculate consecutive losses when a trade closes
  int total = OrdersHistoryTotal();
  if (total != lastTradeCount) {
    lastTradeCount = total;
    RecalcConsecLosses();
    SendAccountData();
  }
}

void RecalcConsecLosses() {
  consecLosses = 0;
  for (int i = OrdersHistoryTotal() - 1; i >= 0; i--) {
    if (!OrderSelect(i, SELECT_BY_POS, MODE_HISTORY)) continue;
    if (OrderType() > OP_SELL) continue; // skip non-trade orders
    if (OrderProfit() + OrderSwap() + OrderCommission() >= 0) break;
    consecLosses++;
    if (consecLosses >= 5) break;
  }
}

void SendAccountData() {
  double balance   = AccountBalance();
  double equity    = AccountEquity();
  double dailyPnl  = balance - dayOpenBalance;
  double dailyPct  = dayOpenBalance > 0 ? (dailyPnl / dayOpenBalance) * 100.0 : 0.0;
  double openLots  = 0;
  for (int i = 0; i < OrdersTotal(); i++) {
    if (OrderSelect(i, SELECT_BY_POS, MODE_TRADES)) openLots += OrderLots();
  }
  if (balance > peakBalance) peakBalance = balance;
  double drawdownPct = peakBalance > 0 ? ((peakBalance - equity) / peakBalance) * 100.0 : 0.0;
  if (drawdownPct < 0) drawdownPct = 0;

  string body = StringFormat(
    "{\\"balance\\":%.2f,\\"equity\\":%.2f,\\"daily_pnl\\":%.2f,\\"daily_pnl_pct\\":%.4f,"
    "\\"consecutive_losses\\":%d,\\"open_lots\\":%.2f,\\"max_drawdown_pct\\":%.4f,\\"platform\\":\\"metatrader4\\"}",
    balance, equity, dailyPnl, dailyPct, consecLosses, openLots, drawdownPct
  );

  string headers = "Content-Type: application/json\\r\\nAuthorization: Bearer " + BearerToken;
  char   post[];  StringToCharArray(body, post);
  char   result[]; string resultHeaders;
  int    timeout = 5000;

  int code = WebRequest("POST", WebhookURL, headers, timeout, post, result, resultHeaders);
  if (code < 0) Print("EdgeKeeper: WebRequest failed — ensure URL is whitelisted in MT4 settings.");
  else          Print("EdgeKeeper: sent. HTTP " + IntegerToString(code));
}
`;
}

function buildMT5EA(token, webhookUrl) {
  return `//+------------------------------------------------------------------+
//|  EdgeKeeper Guardian Layer — MT5 Expert Advisor                  |
//|  Sends live account state to EdgeKeeper every 60 seconds.        |
//|  Setup: Attach to any chart. Tools > Options > Expert Advisors   |
//|         enable "Allow WebRequest for listed URL":                 |
//|         ${webhookUrl.replace('/api/guardian/update', '')}
//+------------------------------------------------------------------+
#property copyright "EdgeKeeper"
#property version   "1.0"

// ── Configuration (pre-filled — do not share this file) ────────────
input string WebhookURL  = "${webhookUrl}";
input string BearerToken = "${token}";
input int    IntervalSec = 60;

// ── State tracking ──────────────────────────────────────────────────
double dayOpenBalance = 0;
int    consecLosses   = 0;
double peakEquity     = 0;
int    lastDealCount  = 0;

int OnInit() {
  dayOpenBalance = AccountInfoDouble(ACCOUNT_BALANCE);
  peakEquity     = AccountInfoDouble(ACCOUNT_EQUITY);
  EventSetTimer(IntervalSec);
  SendAccountData();
  return INIT_SUCCEEDED;
}

void OnDeinit(const int reason) { EventKillTimer(); }

void OnTimer() { SendAccountData(); }

void OnTradeTransaction(const MqlTradeTransaction &trans,
                        const MqlTradeRequest &request,
                        const MqlTradeResult &result) {
  if (trans.type == TRADE_TRANSACTION_DEAL_ADD) {
    RecalcConsecLosses();
    SendAccountData();
  }
}

void RecalcConsecLosses() {
  consecLosses = 0;
  HistorySelect(0, TimeCurrent());
  int total = HistoryDealsTotal();
  for (int i = total - 1; i >= 0; i--) {
    ulong ticket = HistoryDealGetTicket(i);
    if (HistoryDealGetInteger(ticket, DEAL_ENTRY) != DEAL_ENTRY_OUT) continue;
    double profit = HistoryDealGetDouble(ticket, DEAL_PROFIT)
                  + HistoryDealGetDouble(ticket, DEAL_SWAP)
                  + HistoryDealGetDouble(ticket, DEAL_COMMISSION);
    if (profit >= 0) break;
    consecLosses++;
    if (consecLosses >= 5) break;
  }
}

void SendAccountData() {
  double balance   = AccountInfoDouble(ACCOUNT_BALANCE);
  double equity    = AccountInfoDouble(ACCOUNT_EQUITY);
  double dailyPnl  = balance - dayOpenBalance;
  double dailyPct  = dayOpenBalance > 0 ? (dailyPnl / dayOpenBalance) * 100.0 : 0.0;
  if (equity > peakEquity) peakEquity = equity;
  double drawdownPct = peakEquity > 0 ? ((peakEquity - equity) / peakEquity) * 100.0 : 0.0;
  if (drawdownPct < 0) drawdownPct = 0;

  // Sum open lots
  double openLots = 0;
  for (int i = PositionsTotal() - 1; i >= 0; i--) {
    ulong ticket = PositionGetTicket(i);
    if (ticket > 0) openLots += PositionGetDouble(POSITION_VOLUME);
  }

  string body = StringFormat(
    "{\\"balance\\":%.2f,\\"equity\\":%.2f,\\"daily_pnl\\":%.2f,\\"daily_pnl_pct\\":%.4f,"
    "\\"consecutive_losses\\":%d,\\"open_lots\\":%.2f,\\"max_drawdown_pct\\":%.4f,\\"platform\\":\\"metatrader5\\"}",
    balance, equity, dailyPnl, dailyPct, consecLosses, openLots, drawdownPct
  );

  string  headers = "Content-Type: application/json\\r\\nAuthorization: Bearer " + BearerToken;
  uchar   post[];  StringToCharArray(body, post);
  uchar   res[];   string resHeaders;

  int code = WebRequest("POST", WebhookURL, headers, 5000, post, res, resHeaders);
  if (code < 0) Print("EdgeKeeper: WebRequest failed — ensure URL is whitelisted in MT5 settings.");
  else          Print("EdgeKeeper: sent. HTTP " + IntegerToString(code));
}
`;
}

// POST /api/guardian/disconnect — clear guardian connection (Resident+)
app.post('/api/guardian/disconnect', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: discProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const discPlan   = discProfile?.subscription_status || 'free';
  const discBypass = discProfile?.bypass_subscription || false;
  if (!discBypass && !['starter', 'pro', 'institutional'].includes(discPlan)) {
    return res.status(403).json({ error: 'Guardian Layer requires the Resident plan or higher.' });
  }
  const { error } = await supabaseAdmin
    .from('guardian_data')
    .update({ is_connected: false, last_updated: new Date().toISOString() })
    .eq('user_id', req.user.id);

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ ok: true });
});

// GET /api/vault — fetch vault entries (Fellow+ only) — VULN-20 fix
app.get('/api/vault', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: vp } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const vaultPlan   = vp?.subscription_status || 'free';
  const vaultBypass = vp?.bypass_subscription || false;
  if (!vaultBypass && !['pro', 'institutional'].includes(vaultPlan)) {
    return res.status(403).json({ error: 'The Vault requires the Fellow plan or higher.' });
  }

  const limit = Math.min(parseInt(req.query.limit || '20', 10), 50);

  const { data, error } = await supabaseAdmin
    .from('vault_entries')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ entries: data || [], count: (data || []).length });
});

// POST /api/vault — log an intercepted decision (Fellow+ only)
app.post('/api/vault', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: vaultWriteProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const vaultWritePlan   = vaultWriteProfile?.subscription_status || 'free';
  const vaultWriteBypass = vaultWriteProfile?.bypass_subscription || false;
  if (!vaultWriteBypass && !['pro', 'institutional'].includes(vaultWritePlan)) {
    return res.status(403).json({ error: 'The Vault requires the Fellow plan or higher.' });
  }
  const { instrument, direction, lot_size, lock_level, reason, estimated_outcome, mentor } = req.body;
  if (!reason) return res.status(400).json({ error: 'reason is required' });
  // VULN-16: cap reason length
  if (typeof reason !== 'string' || reason.length > 1000) return res.status(400).json({ error: 'reason must be a string under 1000 characters' });

  // Attach current guardian state as context
  const { data: guardianState } = await supabaseAdmin
    .from('guardian_data')
    .select('balance, daily_pnl_pct, consecutive_losses')
    .eq('user_id', req.user.id)
    .maybeSingle();

  const { data, error } = await supabaseAdmin
    .from('vault_entries')
    .insert({
      user_id:            req.user.id,
      instrument:         instrument         || null,
      direction:          direction          || null,
      lot_size:           lot_size           || null,
      lock_level:         lock_level         || 1,
      reason:             reason,
      estimated_outcome:  estimated_outcome  || null,
      mentor:             mentor             || 'mike',
      account_balance:    guardianState?.balance          || null,
      daily_pnl_pct:      guardianState?.daily_pnl_pct    || null,
      consecutive_losses: guardianState?.consecutive_losses || null,
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ entry: data });
});

// ── Trading Rules ─────────────────────────────────────────────────────────────

// GET /api/rules — fetch user's trading rules with violation counts (Resident+)
app.get('/api/rules', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: rulesProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const rulesPlan   = rulesProfile?.subscription_status || 'free';
  const rulesGetBypass = rulesProfile?.bypass_subscription || false;
  if (!rulesGetBypass && !['starter', 'pro', 'institutional'].includes(rulesPlan)) {
    return res.status(403).json({ error: 'Trading Rules require the Resident plan or higher.' });
  }
  const { data, error } = await supabaseAdmin
    .from('rule_violation_summary')
    .select('*')
    .eq('user_id', req.user.id)
    .order('sort_order', { ascending: true })
    .order('rule_created_at', { ascending: true });
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ rules: data || [] });
});

// POST /api/rules — add a new personal law
app.post('/api/rules', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const plan   = profile?.subscription_status || 'free';
  const bypass = profile?.bypass_subscription || false;
  if (!bypass && !['starter', 'pro', 'institutional'].includes(plan)) {
    return res.status(403).json({ error: 'Upgrade to Resident or higher to add personal laws.' });
  }
  const { rule_text, category = 'General', rationale } = req.body;
  if (!rule_text || rule_text.trim().length < 5) {
    return res.status(400).json({ error: 'Rule must be at least 5 characters.' });
  }
  const { data, error } = await supabaseAdmin
    .from('trading_rules')
    .insert({
      user_id:    req.user.id,
      rule_text:  rule_text.trim().slice(0, 500),
      category:   (category || 'General').slice(0, 60),
      rationale:  rationale ? rationale.slice(0, 1000) : null,
      is_active:  true,
    })
    .select()
    .single();
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ rule: data });
});

// PATCH /api/rules/:id — toggle is_active (Resident+)
app.patch('/api/rules/:id', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: patchProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const patchPlan   = patchProfile?.subscription_status || 'free';
  const patchBypass = patchProfile?.bypass_subscription || false;
  if (!patchBypass && !['starter', 'pro', 'institutional'].includes(patchPlan)) {
    return res.status(403).json({ error: 'Trading Rules require the Resident plan or higher.' });
  }
  const { id } = req.params;
  const { is_active } = req.body;
  if (typeof is_active !== 'boolean') {
    return res.status(400).json({ error: 'is_active must be boolean' });
  }
  const { error } = await supabaseAdmin
    .from('trading_rules')
    .update({ is_active })
    .eq('id', id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ ok: true });
});

// DELETE /api/rules/:id — permanently remove a rule (Resident+)
app.delete('/api/rules/:id', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: delProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const delPlan   = delProfile?.subscription_status || 'free';
  const delBypass = delProfile?.bypass_subscription || false;
  if (!delBypass && !['starter', 'pro', 'institutional'].includes(delPlan)) {
    return res.status(403).json({ error: 'Trading Rules require the Resident plan or higher.' });
  }
  const { id } = req.params;
  const { error } = await supabaseAdmin
    .from('trading_rules')
    .delete()
    .eq('id', id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ ok: true });
});

// ── Trader Identity & Readiness ───────────────────────────────────────────────

// PATCH /api/identity — update trader stage, current/target identity
app.patch('/api/identity', requireAuthApi, apiLimiter, async (req, res) => {
  const { trader_stage, current_identity, target_identity } = req.body || {};

  const validStages = ['explorer','student','developing','consistent','performance','mentor_candidate'];
  const update = {};

  if (trader_stage !== undefined) {
    if (!validStages.includes(trader_stage)) {
      return res.status(400).json({ error: 'Invalid trader_stage' });
    }
    update.trader_stage = trader_stage;
  }
  if (current_identity !== undefined) {
    if (typeof current_identity !== 'string' || current_identity.length > 100) {
      return res.status(400).json({ error: 'current_identity must be a string under 100 chars' });
    }
    update.current_identity = current_identity.trim();
  }
  if (target_identity !== undefined) {
    if (typeof target_identity !== 'string' || target_identity.length > 100) {
      return res.status(400).json({ error: 'target_identity must be a string under 100 chars' });
    }
    update.target_identity = target_identity.trim();
  }

  if (Object.keys(update).length === 0) {
    return res.status(400).json({ error: 'Nothing to update' });
  }

  const { error } = await supabaseAdmin
    .from('user_profiles')
    .update(update)
    .eq('id', req.user.id);

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ ok: true, updated: update });
});

// PATCH /api/readiness — update readiness score (server-computed, not user-settable directly)
// Called internally after assessment or after significant events; can also be called by admin
app.patch('/api/readiness', requireAuthApi, adminLimiter, async (req, res) => {
  const adminEmail = process.env.ADMIN_EMAIL || 'alexandermwhitmore@gmail.com';
  if (req.user.email !== adminEmail) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { user_id, score } = req.body || {};
  if (!user_id || typeof score !== 'number' || score < 0 || score > 100) {
    return res.status(400).json({ error: 'user_id and score (0-100) required' });
  }

  const { error } = await supabaseAdmin
    .from('user_profiles')
    .update({ readiness_score: Math.round(score) })
    .eq('id', user_id);

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ ok: true });
});

// ── Milestones ────────────────────────────────────────────────────────────────

// GET /api/milestones — return all achieved milestones for this user
app.get('/api/milestones', requireAuthApi, apiLimiter, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('milestones')
    .select('id, type, label, description, mentor_note, achieved_at')
    .eq('user_id', req.user.id)
    .order('achieved_at', { ascending: true });

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ milestones: data || [] });
});

// POST /api/milestone — record a new milestone achievement
app.post('/api/milestone', requireAuthApi, apiLimiter, async (req, res) => {
  const { type, label, description, mentor_note } = req.body || {};

  if (!type || typeof type !== 'string' || type.length > 60) {
    return res.status(400).json({ error: 'type is required (string, max 60 chars)' });
  }
  if (!label || typeof label !== 'string' || label.length > 120) {
    return res.status(400).json({ error: 'label is required (string, max 120 chars)' });
  }

  // Prevent duplicate milestone types (each type can only be achieved once per user)
  const { data: existing } = await supabaseAdmin
    .from('milestones')
    .select('id')
    .eq('user_id', req.user.id)
    .eq('type', type.trim())
    .maybeSingle();

  if (existing) {
    return res.status(409).json({ error: 'Milestone already achieved', milestone_id: existing.id });
  }

  const { data, error } = await supabaseAdmin
    .from('milestones')
    .insert({
      user_id:     req.user.id,
      type:        type.trim(),
      label:       label.trim().slice(0, 120),
      description: description ? String(description).slice(0, 500) : null,
      mentor_note: mentor_note ? String(mentor_note).slice(0, 500) : null,
    })
    .select()
    .single();

  if (error) return res.status(500).json({ error: 'Database error' });
  res.status(201).json({ milestone: data });
});

// ── Assessment ────────────────────────────────────────────────────────────────

// GET /api/assessment — check whether assessment is complete
app.get('/api/assessment', requireAuthApi, apiLimiter, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('user_profiles')
    .select('assessment_complete')
    .eq('id', req.user.id)
    .maybeSingle();

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ complete: data?.assessment_complete || false });
});

// POST /api/assessment — save assessment results and mark assessment complete
// Assessment answers are stored in the mentor notebook as an 'assessment' fact
app.post('/api/assessment', requireAuthApi, apiLimiter, async (req, res) => {
  const { answers, initial_identity, initial_stage, mentor } = req.body || {};

  if (!answers || typeof answers !== 'object') {
    return res.status(400).json({ error: 'answers object required' });
  }

  const safeMentor = ['mike', 'ashley'].includes(mentor) ? mentor : 'mike';
  const safeStage  = ['explorer','student','developing','consistent','performance','mentor_candidate'].includes(initial_stage)
    ? initial_stage : 'explorer';

  // Validate answer sizes
  const answersStr = JSON.stringify(answers);
  if (answersStr.length > 20000) {
    return res.status(400).json({ error: 'Assessment answers too large' });
  }

  // Update user_profiles: mark assessment complete, set initial stage and identity
  const profileUpdate = { assessment_complete: true, trader_stage: safeStage };
  if (initial_identity && typeof initial_identity === 'string' && initial_identity.length <= 100) {
    profileUpdate.current_identity = initial_identity.trim();
  }

  await supabaseAdmin
    .from('user_profiles')
    .update(profileUpdate)
    .eq('id', req.user.id);

  // Upsert into the notebook: add assessment answers as structured facts
  const { data: existingNb } = await supabaseAdmin
    .from('notebooks')
    .select('facts')
    .eq('user_id', req.user.id)
    .eq('mentor', safeMentor)
    .maybeSingle();

  const existingFacts = existingNb?.facts || [];
  const assessmentFact = {
    type: 'assessment',
    completed_at: new Date().toISOString(),
    ...answers,
  };
  const updatedFacts = [assessmentFact, ...existingFacts.filter(f => f.type !== 'assessment')];

  await supabaseAdmin
    .from('notebooks')
    .upsert(
      { user_id: req.user.id, mentor: safeMentor, facts: updatedFacts },
      { onConflict: 'user_id,mentor' }
    );

  // Award the 'first_assessment' milestone
  await supabaseAdmin
    .from('milestones')
    .upsert(
      {
        user_id: req.user.id,
        type: 'first_assessment',
        label: 'First Assessment Complete',
        description: 'Completed the initial trader profile assessment.',
        mentor_note: 'They showed up and answered honestly. That matters.',
      },
      { onConflict: 'user_id,type' }
    );

  res.json({ ok: true, stage: safeStage });
});

// ── Email helpers ─────────────────────────────────────────────────────────────
const FROM_EMAIL = process.env.FROM_EMAIL || 'EdgeKeeper <mentor@edgekeeper.io>';
const APP_URL    = process.env.APP_URL     || 'https://edgekeeper.io';

async function sendEmail(to, subject, html) {
  if (!resend) return; // silently skip if no key
  try {
    await resend.emails.send({ from: FROM_EMAIL, to, subject, html });
  } catch (err) {
    console.error('Email send error:', err.message);
  }
}

function mentorEmailHtml(mentorName, content, ctaText = 'Open EdgeKeeper', ctaUrl = APP_URL + '/workspace.html') {
  const color = mentorName.toLowerCase() === 'ashley' ? '#6b8c6b' : '#b8a06a';
  return `<!DOCTYPE html><html><body style="background:#050505;color:#d4d0c8;font-family:'Georgia',serif;margin:0;padding:40px 20px;">
  <div style="max-width:520px;margin:0 auto;">
    <div style="font-size:0.65rem;letter-spacing:0.25em;text-transform:uppercase;color:${color};margin-bottom:32px;">EdgeKeeper · ${mentorName}</div>
    <div style="font-size:1.05rem;line-height:1.9;color:#d4d0c8;margin-bottom:36px;">${content}</div>
    <a href="${ctaUrl}" style="display:inline-block;padding:12px 28px;border:1px solid ${color};color:${color};text-decoration:none;font-family:monospace;font-size:0.7rem;letter-spacing:0.15em;text-transform:uppercase;">${ctaText}</a>
    <div style="margin-top:48px;font-size:0.6rem;color:#2a2a2a;font-family:monospace;">EdgeKeeper · Private mentorship for serious traders<br>
    <a href="${APP_URL}/settings.html" style="color:#2a2a2a;">Manage notification preferences</a></div>
  </div></body></html>`;
}

// ── Decision Passport ─────────────────────────────────────────────────────────

// GET /api/passport — fetch recent passport entries + discipline score (Fellow+)
app.get('/api/passport', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: passGetProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const passGetPlan   = passGetProfile?.subscription_status || 'free';
  const passGetBypass = passGetProfile?.bypass_subscription || false;
  if (!passGetBypass && !['pro', 'institutional'].includes(passGetPlan)) {
    return res.status(403).json({ error: 'Decision Passport requires the Fellow plan or higher.' });
  }
  const userId = req.user.id;
  const [entriesResult, scoreResult, rulesResult, vaultResult] = await Promise.all([
    supabaseAdmin
      .from('passport_entries')
      .select('*')
      .eq('user_id', userId)
      .order('entry_date', { ascending: false })
      .limit(30),
    supabaseAdmin
      .from('discipline_scores')
      .select('*')
      .eq('user_id', userId)
      .order('score_date', { ascending: false })
      .limit(1)
      .maybeSingle(),
    supabaseAdmin
      .from('rule_violation_summary')
      .select('total_violations, violations_last_7d')
      .eq('user_id', userId)
      .eq('is_active', true),
    supabaseAdmin
      .from('vault_entries')
      .select('id')
      .eq('user_id', userId),
  ]);

  const rulesData = rulesResult.data || [];
  const totalRules = rulesData.length;
  const rulesWithViolations7d = rulesData.filter(r => (r.violations_last_7d || 0) > 0).length;
  const adherencePct = totalRules > 0 ? Math.round(((totalRules - rulesWithViolations7d) / totalRules) * 100) : null;

  res.json({
    entries:       entriesResult.data || [],
    latestScore:   scoreResult.data   || null,
    ruleAdherence: adherencePct,
    totalRules,
    vaultCount:    (vaultResult.data || []).length,
  });
});

// POST /api/passport — log a new passport entry
app.post('/api/passport', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: passPostProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const passPostPlan   = passPostProfile?.subscription_status || 'free';
  const passPostBypass = passPostProfile?.bypass_subscription || false;
  if (!passPostBypass && !['pro', 'institutional'].includes(passPostPlan)) {
    return res.status(403).json({ error: 'Decision Passport requires the Fellow plan or higher.' });
  }
  const { summary, badge, score, mentor = 'mike' } = req.body;
  if (!summary || summary.trim().length < 5) {
    return res.status(400).json({ error: 'summary required' });
  }
  const { data, error } = await supabaseAdmin
    .from('passport_entries')
    .upsert({
      user_id:    req.user.id,
      entry_date: new Date().toISOString().slice(0, 10),
      summary:    summary.trim().slice(0, 1000),
      badge:      ['disciplined', 'flagged', 'neutral', 'breakthrough'].includes(badge) ? badge : 'neutral',
      score:      score != null ? Math.min(100, Math.max(0, parseInt(score, 10))) : null,
      mentor:     ['mike', 'ashley'].includes(mentor) ? mentor : 'mike',
    }, { onConflict: 'user_id,entry_date' })
    .select()
    .single();
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ entry: data });
});

// ── Behavior Analytics ────────────────────────────────────────────────────────

// GET /api/analytics — aggregate behavioral data for the analytics panel (Fellow+)
app.get('/api/analytics', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: anaProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const anaPlan   = anaProfile?.subscription_status || 'free';
  const anaBypass = anaProfile?.bypass_subscription || false;
  if (!anaBypass && !['pro', 'institutional'].includes(anaPlan)) {
    return res.status(403).json({ error: 'Behavior Analytics requires the Fellow plan or higher.' });
  }
  const userId  = req.user.id;
  const monthKey = new Date().toISOString().slice(0, 7);
  const weekAgo  = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const [usageResult, violationsResult, scoresResult, journalResult, notebookResult] = await Promise.all([
    supabaseAdmin
      .from('message_usage')
      .select('message_count, mentor')
      .eq('user_id', userId)
      .eq('month_key', monthKey),
    supabaseAdmin
      .from('rule_violations')
      .select('id, created_at')
      .eq('user_id', userId)
      .gte('created_at', weekAgo),
    supabaseAdmin
      .from('discipline_scores')
      .select('*')
      .eq('user_id', userId)
      .order('score_date', { ascending: false })
      .limit(7),
    supabaseAdmin
      .from('journal_entries')
      .select('badge, created_at')
      .eq('user_id', userId)
      .gte('created_at', weekAgo),
    supabaseAdmin
      .from('notebooks')
      .select('emotional_map, patterns, strengths')
      .eq('user_id', userId)
      .maybeSingle(),
  ]);

  const usageData    = usageResult.data || [];
  const totalMsgs    = usageData.reduce((s, u) => s + (u.message_count || 0), 0);
  const violations7d = (violationsResult.data || []).length;
  const scores       = scoresResult.data || [];
  const latestScore  = scores[0] || null;
  const journalItems = journalResult.data || [];
  const notebook     = notebookResult.data;

  // Compute rule adherence pct from rule_violation_summary
  const { data: rulesData } = await supabaseAdmin
    .from('rule_violation_summary')
    .select('violations_last_7d, is_active')
    .eq('user_id', userId)
    .eq('is_active', true);

  const totalRules   = (rulesData || []).length;
  const brokenRules  = (rulesData || []).filter(r => (r.violations_last_7d || 0) > 0).length;
  const adherencePct = totalRules > 0 ? Math.round(((totalRules - brokenRules) / totalRules) * 100) : null;

  const behaviorBars = [
    { label: 'Rule Adherence',    pct: adherencePct ?? (latestScore?.rule_adherence ?? null) },
    { label: 'Patience',          pct: latestScore?.patience     ?? null },
    { label: 'Post-Loss Control', pct: latestScore?.post_loss    ?? null },
    { label: 'Risk Discipline',   pct: latestScore?.rule_adherence ?? null },
    { label: 'Execution Clarity', pct: latestScore?.execution    ?? null },
  ];

  // Journal badges this week
  const badgeCounts = journalItems.reduce((acc, e) => {
    acc[e.badge || 'neutral'] = (acc[e.badge || 'neutral'] || 0) + 1;
    return acc;
  }, {});

  res.json({
    sessionsThisMonth: totalMsgs,
    disciplineScore:   latestScore?.overall_score ?? null,
    flagsThisWeek:     violations7d,
    adherencePct,
    totalRules,
    brokenRules,
    behaviorBars,
    badgeCounts,
    scoreHistory:      scores.slice(0, 7).reverse(),
    notebook:          notebook ? { patterns: notebook.patterns, strengths: notebook.strengths } : null,
  });
});

// ── Mentor Messages (proactive outreach inbox) ────────────────────────────────

// GET /api/messages — fetch unread mentor messages
app.get('/api/messages', requireAuthApi, apiLimiter, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('mentor_messages')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(20);
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ messages: data || [] });
});

// PATCH /api/messages/:id — mark a message as read
app.patch('/api/messages/:id', requireAuthApi, apiLimiter, async (req, res) => {
  const { error } = await supabaseAdmin
    .from('mentor_messages')
    .update({ read_at: new Date().toISOString() })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ ok: true });
});

// ── User settings ─────────────────────────────────────────────────────────────

// GET /api/settings — fetch user settings
app.get('/api/settings', requireAuthApi, apiLimiter, async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('user_profiles')
    .select('mentor, email_notifications, proactive_messages, display_name, timezone, subscription_status')
    .eq('id', req.user.id)
    .maybeSingle();
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ settings: data || {} });
});

// PATCH /api/settings — update preferences
app.patch('/api/settings', requireAuthApi, apiLimiter, async (req, res) => {
  const allowed = ['email_notifications', 'proactive_messages', 'display_name', 'timezone', 'mentor'];
  const update  = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) update[key] = req.body[key];
  }
  if (update.mentor && !['mike', 'ashley'].includes(update.mentor)) {
    return res.status(400).json({ error: 'Invalid mentor' });
  }
  if (update.display_name && typeof update.display_name === 'string') {
    update.display_name = update.display_name.trim().slice(0, 60);
  }
  const { error } = await supabaseAdmin
    .from('user_profiles')
    .update(update)
    .eq('id', req.user.id);
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ ok: true });
});

// ── Proactive Mentor Outreach Engine ─────────────────────────────────────────
// Runs on the server as a scheduled job. No human involvement.

async function generateMentorMessage(userId, mentor, triggerType, context = '') {
  const mentorPrompts = {
    mike: `You are Mike, a direct, analytical trading performance mentor. Write a short proactive check-in message to your client. Trigger: ${triggerType}. Context: ${context}. Be direct, observational, warm. 2-3 sentences max. No greeting. Never start with "I". Sound like their older, wiser self.`,
    ashley: `You are Ashley, an empathetic, holistic trading performance mentor. Write a short proactive check-in message to your client. Trigger: ${triggerType}. Context: ${context}. Be warm, perceptive. 2-3 sentences max. No greeting. Never start with "I".`,
  };

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return null;

  try {
    const upstream = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [{ role: 'system', content: mentorPrompts[mentor] || mentorPrompts.mike }],
        max_completion_tokens: 120,
      }),
    });
    const data = await upstream.json();
    return (data.choices?.[0]?.message?.content || '').trim();
  } catch (_) { return null; }
}

async function runProactiveOutreach() {
  try {
    // Find Fellow+ users who have proactive messages enabled
    const { data: users } = await supabaseAdmin
      .from('user_profiles')
      .select('id, mentor, email_notifications, proactive_messages, subscription_status')
      .in('subscription_status', ['starter', 'pro', 'institutional'])
      .eq('proactive_messages', true);

    if (!users?.length) return;

    for (const user of users) {
      // Check last message
      const { data: usage } = await supabaseAdmin
        .from('message_usage')
        .select('updated_at')
        .eq('user_id', user.id)
        .order('updated_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      const lastActivity = usage?.updated_at ? new Date(usage.updated_at) : null;
      const daysSinceActivity = lastActivity
        ? Math.floor((Date.now() - lastActivity.getTime()) / 86400000)
        : 999;

      if (daysSinceActivity < 3) continue;

      // Check if we already sent an outreach this week
      const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      const { data: recentMsg } = await supabaseAdmin
        .from('mentor_messages')
        .select('id')
        .eq('user_id', user.id)
        .eq('trigger_type', 'inactivity')
        .gte('created_at', weekAgo)
        .maybeSingle();

      if (recentMsg) continue; // already sent this week

      const context = `User has been away for ${daysSinceActivity} days.`;
      const content = await generateMentorMessage(user.id, user.mentor || 'mike', 'inactivity', context);
      if (!content) continue;

      // Store the message in DB
      await supabaseAdmin.from('mentor_messages').insert({
        user_id:      user.id,
        mentor:       user.mentor || 'mike',
        content,
        trigger_type: 'inactivity',
      });

      // Send email if user has email notifications on
      if (user.email_notifications !== false) {
        const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(user.id);
        const email = authUser?.user?.email;
        if (email) {
          const mentorName = (user.mentor || 'mike') === 'ashley' ? 'Ashley' : 'Mike';
          await sendEmail(
            email,
            `${mentorName} wants to check in`,
            mentorEmailHtml(mentorName, content.replace(/\n/g, '<br>'), 'Resume your session', APP_URL + '/workspace.html')
          );
        }
      }
    }
  } catch (err) {
    console.error('Proactive outreach error:', err.message);
  }
}

// DELETE /api/account — permanently delete the user's account and all data
app.delete('/api/account', requireAuthApi, apiLimiter, async (req, res) => {
  const userId = req.user.id;
  try {
    // Delete user data in dependency order (FKs from child to parent)
    const tables = [
      'rule_violations', 'journal_entries', 'trading_rules',
      'vault_entries', 'mentor_messages', 'message_usage', 'voice_usage',
      'guardian_data', 'guardian_accounts', 'decision_passport',
      'discipline_scores', 'subscriptions', 'notebooks', 'user_profiles',
    ];
    for (const table of tables) {
      await supabaseAdmin.from(table).delete().eq('user_id', userId).catch(() => {});
    }
    // Delete the auth user last
    await supabaseAdmin.auth.admin.deleteUser(userId);
    // Clear session cookie
    res.clearCookie('ek_session', { httpOnly: true, sameSite: 'lax', path: '/' });
    res.json({ ok: true });
  } catch (err) {
    console.error('Account delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete account. Please contact support.' });
  }
});

// ── Billing — Paystack: initiate subscription ─────────────────────────────────
app.post('/api/billing/initiate', requireAuthApi, apiLimiter, async (req, res) => {
  const { plan, billing = 'monthly' } = req.body;
  if (!['starter', 'pro', 'institutional'].includes(plan)) {
    return res.status(400).json({ error: 'Invalid plan' });
  }
  if (plan === 'institutional') {
    return res.json({ type: 'contact', email: process.env.CONTACT_EMAIL || 'hello@edgekeeper.io' });
  }

  if (!req.user.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(req.user.email)) {
    return res.status(400).json({ error: 'Invalid user email for billing' });
  }

  // Server-side double-charge guard: refuse to open a new Paystack session if
  // the user is already on the requested plan or higher. The client performs
  // the same check but it can be bypassed by direct API calls.
  try {
    const { data: profile } = await supabaseAdmin
      .from('user_profiles')
      .select('subscription_status, bypass_subscription')
      .eq('id', req.user.id)
      .maybeSingle();

    if (profile?.bypass_subscription) {
      return res.status(409).json({ error: 'Account has a manual subscription override — no billing needed.' });
    }

    const PLAN_RANK  = { free: 0, starter: 1, pro: 2, institutional: 3 };
    const currentPlan = profile?.subscription_status || 'free';
    if ((PLAN_RANK[currentPlan] ?? 0) >= (PLAN_RANK[plan] ?? 1)) {
      return res.status(409).json({
        error: `Already on ${currentPlan} plan — no upgrade needed.`,
        current_plan: currentPlan,
      });
    }
  } catch (profileCheckErr) {
    console.error('Billing plan pre-check error:', profileCheckErr.message);
    // Non-fatal — continue and let Paystack handle idempotency
  }

  const paystackKey = process.env.PAYSTACK_SECRET_KEY;
  if (!paystackKey || paystackKey.startsWith('sk_test_placeholder')) {
    return res.status(501).json({ error: 'Payment not yet configured' });
  }

  const planCodeEnv = `PAYSTACK_PLAN_${plan.toUpperCase()}_${billing === 'annual' ? 'ANNUAL' : 'MONTHLY'}`;
  const planCode    = process.env[planCodeEnv];
  if (!planCode) {
    console.error(`Paystack plan code not configured: ${planCodeEnv}`);
    return res.status(501).json({ error: 'Payment plan not yet configured' });
  }

  try {
    const body = JSON.stringify({
      email:        req.user.email,
      plan:         planCode,
      callback_url: `${process.env.APP_URL || 'http://localhost:3000'}/billing/callback`,
      metadata: JSON.stringify({ user_id: req.user.id, plan, billing }),
    });

    const upstream = await fetch('https://api.paystack.co/transaction/initialize', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${paystackKey}` },
      body,
    });
    const data = await upstream.json();
    if (!data.status) {
      console.error('Paystack init error:', data.message);
      return res.status(502).json({ error: 'Payment initiation failed' });
    }
    res.json({ url: data.data.authorization_url, reference: data.data.reference });
  } catch (err) {
    console.error('Billing initiate error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Billing — Paystack: callback after payment ────────────────────────────────
app.get('/billing/callback', requireAuthPage, async (req, res) => {
  const { reference } = req.query;
  if (!reference) return res.redirect('/workspace.html');

  const paystackKey = process.env.PAYSTACK_SECRET_KEY;
  let paymentSucceeded = false;
  try {
    const upstream = await fetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${paystackKey}` } }
    );
    const data = await upstream.json();

    if (data.status && data.data?.status === 'success') {
      let meta = data.data.metadata || {};
      if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch (_) { meta = {}; } }

      // Guard: only update the authenticated user — never trust metadata.user_id
      // to update a different account (prevents privilege escalation via crafted
      // Paystack transactions).
      if (meta.user_id && meta.user_id !== req.user.id) {
        console.error('Billing callback user_id mismatch — possible tampering', {
          session_user: req.user.id,
          meta_user:    meta.user_id,
        });
        return res.redirect('/workspace.html?payment=error');
      }

      const VALID_CB_PLANS = ['free', 'starter', 'pro', 'institutional'];
      const plan = VALID_CB_PLANS.includes(meta.plan) ? meta.plan : 'starter';

      await supabaseAdmin.from('user_profiles')
        .update({ subscription_status: plan })
        .eq('id', req.user.id);

      await supabaseAdmin.from('subscriptions').upsert({
        user_id:                 req.user.id,
        payment_subscription_id: data.data.subscription?.subscription_code || reference,
        payment_customer_code:   data.data.customer?.customer_code || null,
        plan,
        status: 'active',
      }, { onConflict: 'user_id' });

      paymentSucceeded = true;
    } else {
      // Transaction was abandoned, declined, or failed — log for visibility.
      const txStatus = data.data?.status || 'unknown';
      console.warn('Billing callback: non-success transaction', {
        reference,
        status: txStatus,
        user_id: req.user.id,
      });
    }
  } catch (err) {
    console.error('Billing callback error:', err.message);
  }

  // Only show ?subscribed=1 when payment actually succeeded.
  // A failed/abandoned payment redirects with ?payment=failed so the workspace
  // can surface a helpful message instead of silently implying success.
  res.redirect(paymentSucceeded ? '/workspace.html?subscribed=1' : '/workspace.html?payment=failed');
});

// ── Billing — Paystack webhook ────────────────────────────────────────────────
// Raw body required for HMAC-SHA512 signature verification
app.post(
  '/api/billing/webhook',
  express.raw({ type: 'application/json', limit: '1mb' }),
  async (req, res) => {
    const secret    = process.env.PAYSTACK_SECRET_KEY || '';
    const signature = req.headers['x-paystack-signature'] || '';
    const hash      = crypto.createHmac('sha512', secret).update(req.body).digest('hex');

    if (hash !== signature) return res.status(401).json({ error: 'Invalid signature' });

    let event;
    try { event = JSON.parse(req.body.toString()); } catch (_) {
      return res.status(400).json({ error: 'Invalid JSON' });
    }

    // Acknowledge immediately — process async
    res.json({ status: true });

    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const VALID_PLANS = ['free', 'starter', 'pro', 'institutional'];

    try {
      // Dedup: skip retried webhook deliveries that have already been processed.
      const eventId = event.id ? String(event.id) : null;
      if (eventId) {
        const { error: dedupErr } = await supabaseAdmin
          .from('webhook_events')
          .insert({ event_id: eventId, event_type: event.event || 'unknown' });
        if (dedupErr) {
          // Unique constraint violation = already processed
          console.log('Webhook already processed, skipping:', eventId, event.event);
          return;
        }
      }
    } catch (dedupCheckErr) {
      // VULN-10: dedup failure is fatal — safer to miss an event than to double-apply a disable
      console.error('Webhook dedup check error, skipping event to avoid double-processing:', dedupCheckErr.message);
      return;
    }

    try {
      let meta = event.data?.metadata || {};
      if (typeof meta === 'string') { try { meta = JSON.parse(meta); } catch (_) { meta = {}; } }
      const userId = meta.user_id;
      const plan   = meta.plan;

      // Validate both fields before touching the DB
      if (userId && !UUID_RE.test(userId)) {
        console.error('Webhook: invalid user_id shape — ignoring', { userId });
        return;
      }

      if (event.event === 'charge.success' || event.event === 'subscription.create') {
        if (userId && plan && VALID_PLANS.includes(plan)) {
          await supabaseAdmin.from('user_profiles')
            .update({ subscription_status: plan })
            .eq('id', userId);
        }
      } else if (event.event === 'subscription.disable' || event.event === 'invoice.payment_failed') {
        if (userId) {
          await supabaseAdmin.from('user_profiles')
            .update({ subscription_status: 'free' })
            .eq('id', userId);
        }
      }
    } catch (err) {
      console.error('Webhook processing error:', err.message);
    }
  }
);

// ── Director AI — admin-only orchestration endpoint ───────────────────────────
const DIRECTOR_SYSTEM_PROMPT = `You are the Director of EdgeKeeper's internal AI team. EdgeKeeper is a trading psychology AI mentorship platform for retail and prop traders. Features: AI mentors Mike (analytical) and Ashley (empathetic), voice sessions, trading journal, rules engine, Guardian Layer (live account monitoring), The Vault (intervention archive), and proactive mentor outreach. Stack: Node.js/Express, Supabase, OpenAI GPT-4o-mini, ElevenLabs voice, Paystack billing.

Your team:
— Claude: Chief Architect & Lead Engineer. Full-stack ownership, auth, AI proxy, security, payments, migrations.
— Zara: Head of Design & Frontend. UI/UX, animations, design consistency.
— Rex: Security & Backend Lead. HSTS, rate limiting, input validation, hardening.
— Atlas: Product Strategist. Roadmap, audit, SEO, feature prioritisation.
— Nova: Design Systems Lead. Token alignment, typography enforcement, cross-page consistency.
— Kai: AI & Voice Integration Lead. Prompt engineering, ElevenLabs, voice quality.
— Milo: Growth & Marketing Lead. Landing page conversion, prop firm outreach, content.
— Sage: Head of Customer Experience. Onboarding flow, user retention, support frameworks.
— Phoenix: Revenue & Partnerships Lead. Paystack integration, prop firm deals, pricing strategy.
— Leo: Data & Analytics Lead. Session instrumentation, behaviour scoring, PostHog/Plausible.
— Maya: Content & Community Lead. Blog, LinkedIn, trading community presence.

When the founder talks to you, understand what they want, identify which team members need to act, and respond with: (1) a clear summary of what you understood, (2) a delegation plan naming each responsible worker and their specific task, (3) any blockers or decisions the founder needs to make first. Be direct. No filler. You are a senior operator who gets things done.`;

app.post('/api/director/chat', requireAdmin, adminLimiter, async (req, res) => {
  const { message } = req.body || {};
  if (!message || typeof message !== 'string' || message.length > 4000) {
    return res.status(400).json({ error: 'message is required (max 4000 chars)' });
  }

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey || apiKey === 'your-openai-key-here') {
    return res.status(503).json({ error: 'AI service not configured' });
  }

  try {
    const upstream = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: DIRECTOR_SYSTEM_PROMPT },
          { role: 'user',   content: message },
        ],
        max_completion_tokens: 800,
      }),
    });

    if (!upstream.ok) {
      return res.status(502).json({ error: 'AI service error' });
    }

    const data    = await upstream.json();
    const content = (data.choices?.[0]?.message?.content || '').trim();

    // Persist to office_messages so it appears in group chat
    await supabaseAdmin.from('office_messages').insert([
      { worker_id: 'founder', worker_name: 'Founder', avatar_char: 'F', content: message,  msg_type: 'chat'     },
      { worker_id: 'director', worker_name: 'Director', avatar_char: 'D', content, msg_type: 'director' },
    ]);

    res.json({ content });
  } catch (err) {
    console.error('Director chat error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ── Office messages — group chat feed ─────────────────────────────────────────
app.get('/api/office/messages', requireAdmin, adminLimiter, async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit || '50', 10), 100);
  const before = req.query.before; // ISO timestamp for pagination
  let query = supabaseAdmin
    .from('office_messages')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(limit);
  if (before) query = query.lt('created_at', before);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ messages: (data || []).reverse() });
});

app.post('/api/office/messages', requireAdmin, adminLimiter, async (req, res) => {
  const { content, worker_id = 'founder', worker_name = 'Founder' } = req.body || {};
  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'content is required' });
  }
  const { data, error } = await supabaseAdmin.from('office_messages').insert({
    worker_id,
    worker_name,
    avatar_char: worker_name[0]?.toUpperCase() || 'F',
    content: content.trim().slice(0, 4000),
    msg_type: 'chat',
  }).select().single();
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ message: data });
});

// ── Admin API: list all users ─────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, adminLimiter, async (req, res) => {
  try {
    const [profilesRes, authRes] = await Promise.all([
      supabaseAdmin.from('user_profiles').select(
        'id, mentor, onboarding_complete, subscription_status, bypass_subscription, is_admin, created_at'
      ).order('created_at', { ascending: false }),
      supabaseAdmin.auth.admin.listUsers({ perPage: 1000 }),
    ]);

    if (profilesRes.error) throw profilesRes.error;

    const emailMap = {};
    (authRes.data?.users || []).forEach(u => {
      emailMap[u.id] = { email: u.email, last_sign_in: u.last_sign_in_at };
    });

    const users = (profilesRes.data || []).map(p => ({
      ...p,
      email:        emailMap[p.id]?.email        || '—',
      last_sign_in: emailMap[p.id]?.last_sign_in || null,
    }));

    res.json({ users });
  } catch (err) {
    console.error('Admin users error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// ── Admin API: update user (bypass, plan) ────────────────────────────────────
app.patch('/api/admin/users/:id', requireAdmin, adminLimiter, async (req, res) => {
  const { id } = req.params;
  const allowed = ['bypass_subscription', 'subscription_status'];
  const updates = {};
  for (const k of allowed) {
    if (req.body[k] !== undefined) updates[k] = req.body[k];
  }
  if (Object.keys(updates).length === 0) {
    return res.status(400).json({ error: 'No valid fields provided' });
  }

  const validPlans = ['free', 'starter', 'pro', 'institutional'];
  if (updates.subscription_status && !validPlans.includes(updates.subscription_status)) {
    return res.status(400).json({ error: 'Invalid subscription_status' });
  }

  const { data, error } = await supabaseAdmin
    .from('user_profiles')
    .update(updates)
    .eq('id', id)
    .select()
    .single();

  if (error) {
    console.error('Admin update error:', error.message);
    return res.status(500).json({ error: 'Database error' });
  }
  res.json({ user: data });
});

// ── Admin: live platform stats ────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, adminLimiter, async (req, res) => {
  try {
    const monthKey = new Date().toISOString().slice(0, 7);
    const [profilesRes, usageRes, voiceRes, journalRes, msgRes] = await Promise.all([
      supabaseAdmin.from('user_profiles').select('subscription_status, onboarding_complete', { count: 'exact' }),
      supabaseAdmin.from('message_usage').select('message_count').eq('month_key', monthKey),
      supabaseAdmin.from('voice_usage').select('session_count').eq('month_key', monthKey),
      supabaseAdmin.from('journal_entries').select('id', { count: 'exact' }),
      supabaseAdmin.from('office_messages').select('id', { count: 'exact' }),
    ]);

    const profiles = profilesRes.data || [];
    const planCounts = profiles.reduce((acc, p) => {
      const k = p.subscription_status || 'free';
      acc[k] = (acc[k] || 0) + 1;
      return acc;
    }, {});

    const totalMessages = (usageRes.data || []).reduce((s, r) => s + (r.message_count || 0), 0);
    const totalVoice    = (voiceRes.data || []).reduce((s, r) => s + (r.session_count || 0), 0);

    res.json({
      users: {
        total:       profiles.length,
        onboarded:   profiles.filter(p => p.onboarding_complete).length,
        by_plan:     planCounts,
      },
      this_month: {
        ai_exchanges:   totalMessages,
        voice_sessions: totalVoice,
      },
      all_time: {
        journal_entries: journalRes.count || 0,
        office_messages: msgRes.count    || 0,
      },
    });
  } catch (err) {
    console.error('Admin stats error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// ── Admin: manually trigger proactive outreach ────────────────────────────────
app.post('/api/admin/run-outreach', requireAdmin, adminLimiter, async (req, res) => {
  res.json({ ok: true, message: 'Outreach job triggered — check server logs.' });
  // Fire async; don't await so the response returns immediately
  runProactiveOutreach().catch(err => console.error('Manual outreach error:', err.message));
});

// ── Admin: broadcast system announcement to all active users ─────────────────
// Writes a mentor_messages row for every onboarded user
app.post('/api/admin/announce', requireAdmin, adminLimiter, async (req, res) => {
  const { content, mentor = 'mike' } = req.body || {};
  if (!content || typeof content !== 'string' || content.trim().length < 5) {
    return res.status(400).json({ error: 'content required (min 5 chars)' });
  }
  if (!['mike', 'ashley'].includes(mentor)) {
    return res.status(400).json({ error: 'mentor must be mike or ashley' });
  }

  try {
    const { data: users } = await supabaseAdmin
      .from('user_profiles')
      .select('id')
      .eq('onboarding_complete', true);

    if (!users?.length) return res.json({ sent: 0 });

    const rows = users.map(u => ({
      user_id:      u.id,
      mentor,
      content:      content.trim().slice(0, 2000),
      trigger_type: 'admin_announce',
    }));

    const { error } = await supabaseAdmin.from('mentor_messages').insert(rows);
    if (error) throw error;

    // Also post to office chat so the team sees it was sent
    await supabaseAdmin.from('office_messages').insert({
      worker_id:   'founder',
      worker_name: 'Founder',
      avatar_char: 'F',
      content:     `Announcement sent to ${users.length} user${users.length !== 1 ? 's' : ''} via ${mentor === 'ashley' ? 'Ashley' : 'Mike'}: "${content.trim().slice(0, 80)}${content.trim().length > 80 ? '…' : ''}"`,
      msg_type:    'status',
    });

    res.json({ sent: users.length });
  } catch (err) {
    console.error('Announce error:', err.message);
    res.status(500).json({ error: 'Database error' });
  }
});

// ── Admin: post a system message to the office feed ──────────────────────────
app.post('/api/admin/office-system', requireAdmin, adminLimiter, async (req, res) => {
  const { content, worker_id = 'system', worker_name = 'System' } = req.body || {};
  if (!content || typeof content !== 'string') {
    return res.status(400).json({ error: 'content required' });
  }
  const { data, error } = await supabaseAdmin.from('office_messages').insert({
    worker_id,
    worker_name,
    avatar_char: worker_name[0]?.toUpperCase() || 'S',
    content: content.trim().slice(0, 4000),
    msg_type: 'system',
  }).select().single();
  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ message: data });
});

// ── Behavioral Reports ────────────────────────────────────────────────────────
// GET /api/reports — list reports for the authenticated user (Fellow+ only)
app.get('/api/reports', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();

  const plan   = profile?.subscription_status || 'free';
  const bypass = profile?.bypass_subscription || false;
  if (!bypass && !['pro', 'institutional'].includes(plan)) {
    return res.status(403).json({ error: 'Monthly reports are available on the Fellow plan and above.' });
  }

  const { data, error } = await supabaseAdmin
    .from('behavioral_reports')
    .select('*')
    .eq('user_id', req.user.id)
    .order('report_month', { ascending: false })
    .limit(12);

  if (error) return res.status(500).json({ error: 'Database error' });
  res.json({ reports: data || [] });
});

// POST /api/reports/generate — manually trigger a report (Fellow+ only)
app.post('/api/reports/generate', requireAuthApi, apiLimiter, async (req, res) => {
  const { data: rptGenProfile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription')
    .eq('id', req.user.id)
    .maybeSingle();
  const rptGenPlan   = rptGenProfile?.subscription_status || 'free';
  const rptGenBypass = rptGenProfile?.bypass_subscription || false;
  if (!rptGenBypass && !['pro', 'institutional'].includes(rptGenPlan)) {
    return res.status(403).json({ error: 'Monthly reports are available on the Fellow plan and above.' });
  }
  const { month } = req.body; // optional override, e.g. '2026-05'
  const reportMonth = month || new Date().toISOString().slice(0, 7);
  res.json({ ok: true, message: 'Report generation started.' });
  generateBehavioralReport(req.user.id, reportMonth).catch(err =>
    console.error('Report generation error:', err.message)
  );
});

async function generateBehavioralReport(userId, reportMonth) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return;

  // Check plan
  const { data: profile } = await supabaseAdmin
    .from('user_profiles')
    .select('subscription_status, bypass_subscription, mentor')
    .eq('id', userId)
    .maybeSingle();

  const plan   = profile?.subscription_status || 'free';
  const bypass = profile?.bypass_subscription || false;
  if (!bypass && !['pro', 'institutional'].includes(plan)) return;

  const mentor = profile?.mentor || 'mike';
  const [year, month] = reportMonth.split('-').map(Number);
  const startOfMonth = new Date(year, month - 1, 1).toISOString();
  const endOfMonth   = new Date(year, month, 1).toISOString();

  const [journalRes, violationsRes, scoresRes] = await Promise.all([
    supabaseAdmin.from('journal_entries')
      .select('content, entry_type, created_at')
      .eq('user_id', userId)
      .gte('created_at', startOfMonth)
      .lt('created_at', endOfMonth)
      .order('created_at', { ascending: false })
      .limit(30),
    supabaseAdmin.from('rule_violations')
      .select('mentor_note, evidence_quote, created_at')
      .eq('user_id', userId)
      .gte('created_at', startOfMonth)
      .lt('created_at', endOfMonth),
    supabaseAdmin.from('discipline_scores')
      .select('overall_score, created_at')
      .eq('user_id', userId)
      .gte('created_at', startOfMonth)
      .lt('created_at', endOfMonth)
      .order('created_at', { ascending: false })
      .limit(10),
  ]);

  const entries    = journalRes.data    || [];
  const violations = violationsRes.data || [];
  const scores     = scoresRes.data     || [];

  const avgScore = scores.length
    ? Math.round(scores.reduce((s, x) => s + (x.overall_score || 0), 0) / scores.length)
    : null;

  const mentorVoice = mentor === 'ashley'
    ? 'Ashley: warm, empathetic, holistic perspective on emotional and psychological patterns'
    : 'Mike: direct, analytical, performance-focused observations on discipline and execution';

  const journalExcerpts = entries.slice(0, 8)
    .map(e => e.content.slice(0, 300))
    .join('\n---\n');

  const violationNotes = violations.map(v => v.mentor_note).join(' | ');

  const systemPrompt = `You are ${mentorVoice}. Write a monthly behavioral performance report for a trader based on their data. Be honest, specific, and constructive. Write in first person as the mentor. No generic advice — everything must be grounded in the data provided.

Respond ONLY with valid JSON:
{
  "summary": "2-3 paragraph narrative (400-600 words) of the month's behavioral performance",
  "strengths": ["strength 1", "strength 2", "strength 3"],
  "patterns": ["observed pattern 1", "observed pattern 2"],
  "focus_areas": ["what to work on next month 1", "what to work on 2"]
}`;

  const userMsg = `Report month: ${reportMonth}
Journal entries this month: ${entries.length}
Rule violations: ${violations.length}${violationNotes ? `\nViolation notes: ${violationNotes.slice(0, 600)}` : ''}
Average discipline score: ${avgScore !== null ? avgScore + '/100' : 'N/A'}
Journal excerpts:\n${journalExcerpts || '(no entries this month)'}`;

  try {
    const upstream = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify({
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user',   content: userMsg },
        ],
        max_completion_tokens: 900,
        response_format: { type: 'json_object' },
      }),
    });

    const gptData = await upstream.json();
    const raw = gptData.choices?.[0]?.message?.content || '{}';
    let parsed;
    try { parsed = JSON.parse(raw); } catch (_) { parsed = {}; }

    await supabaseAdmin.from('behavioral_reports').upsert({
      user_id:      userId,
      report_month: reportMonth,
      mentor,
      summary:      (parsed.summary || 'Report unavailable.').slice(0, 3000),
      strengths:    Array.isArray(parsed.strengths)   ? parsed.strengths.slice(0, 5)   : [],
      patterns:     Array.isArray(parsed.patterns)    ? parsed.patterns.slice(0, 5)    : [],
      focus_areas:  Array.isArray(parsed.focus_areas) ? parsed.focus_areas.slice(0, 4) : [],
      stats: {
        journal_entries: entries.length,
        rule_violations: violations.length,
        avg_score:       avgScore,
        scores_recorded: scores.length,
      },
    }, { onConflict: 'user_id,report_month' });

  } catch (err) {
    console.error('Report GPT error:', err.message);
  }
}

// ── Catch-all 404 ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  const page404 = path.join(__dirname, '404.html');
  if (fs.existsSync(page404)) res.status(404).sendFile(page404);
  else res.status(404).send('Not found');
});

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Vercel Cron endpoints ─────────────────────────────────────────────────────
// Vercel calls these HTTP routes on schedule (defined in vercel.json).
// A shared secret prevents public abuse — set CRON_SECRET in Vercel env vars.
function verifyCronSecret(req, res, next) {
  const secret = process.env.CRON_SECRET;
  if (secret && req.headers.authorization !== `Bearer ${secret}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/api/cron/outreach', verifyCronSecret, async (req, res) => {
  try {
    await runProactiveOutreach();
    res.json({ ok: true });
  } catch (err) {
    console.error('Proactive outreach error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cron/reports', verifyCronSecret, async (req, res) => {
  const prevMonth = new Date();
  prevMonth.setDate(0);
  const reportMonth = prevMonth.toISOString().slice(0, 7);
  try {
    const { data: users } = await supabaseAdmin
      .from('user_profiles')
      .select('id')
      .in('subscription_status', ['pro', 'institutional']);
    if (users?.length) {
      for (const u of users) {
        await generateBehavioralReport(u.id, reportMonth).catch(err =>
          console.error(`[Reports] Error for user ${u.id}:`, err.message)
        );
      }
    }
    res.json({ ok: true, reports: users?.length ?? 0, month: reportMonth });
  } catch (err) {
    console.error('[Reports] Cron error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Local dev server ──────────────────────────────────────────────────────────
// Only binds a port when run directly (`node server.js`).
// Vercel imports this file and uses `module.exports` — never calls listen().
if (require.main === module) {
  const warnings = [];
  if (!process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY === 'your-openai-key-here')
    warnings.push('OPENAI_API_KEY not set — AI responses will fail');
  if (!process.env.SUPABASE_URL || process.env.SUPABASE_URL === 'https://your-project.supabase.co')
    warnings.push('SUPABASE_URL not set — auth and data will fail');
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY.startsWith('placeholder'))
    warnings.push('SUPABASE_SERVICE_ROLE_KEY not set — server-side auth will fail');
  if (!process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_SECRET_KEY.startsWith('sk_live_your'))
    warnings.push('PAYSTACK_SECRET_KEY not set — payments will fail');
  if (process.env.NODE_ENV === 'production' && !process.env.APP_URL) {
    console.error('FATAL: APP_URL must be set in production. Shutting down.');
    process.exit(1);
  }
  if (!process.env.APP_URL)
    warnings.push('APP_URL not set — CORS and email links will use localhost fallback');

  app.listen(PORT, HOST, () => {
    console.log(`\nEdgeKeeper server → http://${HOST}:${PORT}\n`);
    if (warnings.length) {
      console.warn('  Configuration warnings:');
      for (const w of warnings) console.warn('  ⚠  ' + w);
      console.warn('');
    }

    cron.schedule('0 9 * * *', () => {
      runProactiveOutreach().catch(err => console.error('Proactive outreach error:', err.message));
    });
    console.log('  Proactive outreach cron scheduled (09:00 daily)');

    cron.schedule('0 6 1 * *', async () => {
      const prevMonth = new Date();
      prevMonth.setDate(0);
      const reportMonth = prevMonth.toISOString().slice(0, 7);
      console.log(`[Reports] Generating monthly reports for ${reportMonth}…`);
      try {
        const { data: users } = await supabaseAdmin
          .from('user_profiles').select('id')
          .in('subscription_status', ['pro', 'institutional']);
        if (users?.length) {
          for (const u of users) {
            await generateBehavioralReport(u.id, reportMonth).catch(err =>
              console.error(`[Reports] Error for user ${u.id}:`, err.message)
            );
          }
          console.log(`[Reports] Done — ${users.length} report(s) generated.`);
        }
      } catch (err) {
        console.error('[Reports] Cron error:', err.message);
      }
    });
    console.log('  Monthly reports cron scheduled (1st of month, 06:00)\n');
  });
}

// Vercel serverless entry point — exports the Express app as the request handler
module.exports = app;
