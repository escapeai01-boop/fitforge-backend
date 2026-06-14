// FitForge Backend v2.3 — Prompt analyze-food renforcé (valeurs nutritionnelles de référence)
// v2.2 : PostgreSQL persistant

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 8080;

// ─── Config ──────────────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'fitforge-secret-change-me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_MONTHLY = process.env.STRIPE_PRICE_MONTHLY || '';
const STRIPE_PRICE_ANNUAL = process.env.STRIPE_PRICE_ANNUAL || '';

const ALLOWED_ORIGINS = [
  'https://escapeai01-boop.github.io',
  'http://localhost:8080',
  'http://localhost:3000',
  'null'
];

// ─── PostgreSQL ───────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // requis pour Railway
});

// Création des tables au démarrage (idempotent)
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      subscription_status TEXT NOT NULL DEFAULT 'trial',
      trial_ends_at BIGINT,
      subscription_ends_at BIGINT,
      plan TEXT,
      stripe_customer_id TEXT,
      quotas_used JSONB NOT NULL DEFAULT '{"photo_scans":0,"recipes":0,"programs":0,"coach_messages":0}',
      extra_quotas JSONB NOT NULL DEFAULT '{"photo_scans":0,"recipes":0,"programs":0,"coach_messages":0}',
      quota_reset_date BIGINT
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL,
      created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW()) * 1000
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    CREATE INDEX IF NOT EXISTS idx_users_stripe ON users(stripe_customer_id);
  `);
  console.log('✅ Tables PostgreSQL prêtes');

  // Nettoyage sessions expirées au démarrage
  await pool.query('DELETE FROM sessions WHERE expires_at < $1', [Date.now()]);
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: function(origin, callback) {
    // Autoriser : pas d'origin (navigateur direct, curl) OU origine connue
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error('CORS: origine non autorisée — ' + origin));
  },
  credentials: true
}));

app.use('/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10mb' }));

// ─── Rate limiting ────────────────────────────────────────────────────────────
const RATE_LIMITS = new Map();

function rateLimit(maxRequests, windowMs) {
  return function(req, res, next) {
    const key = (req.ip || 'unknown') + req.path;
    const now = Date.now();
    const entry = RATE_LIMITS.get(key);
    if (!entry || now > entry.reset_at) {
      RATE_LIMITS.set(key, { count: 1, reset_at: now + windowMs });
      return next();
    }
    if (entry.count >= maxRequests) {
      const retryAfter = Math.ceil((entry.reset_at - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({ error: 'Trop de tentatives — réessaie dans ' + retryAfter + ' secondes', code: 'RATE_LIMITED' });
    }
    entry.count++;
    next();
  };
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of RATE_LIMITS.entries()) {
    if (now > entry.reset_at) RATE_LIMITS.delete(key);
  }
}, 60 * 60 * 1000);

// ─── Quotas ───────────────────────────────────────────────────────────────────
const DEFAULT_QUOTAS = {
  photo_scans: 60,
  recipes: 20,
  programs: 5,
  coach_messages: 50
};

const CLAUDE_CONFIG = {
  model: 'claude-sonnet-4-6',
  max_tokens_by_route: {
    'analyze-food': 1800,
    'generate-recipe': 3000,
    'generate-program': 8000,
    'coach': 1000
  }
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
function hashPassword(password) {
  const salt = JWT_SECRET.slice(0, 16);
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function isSubscriptionActive(user) {
  if (!user) return false;
  const now = Date.now();
  if (user.subscription_status === 'trial') return Number(user.trial_ends_at) > now;
  if (user.subscription_status === 'active') return Number(user.subscription_ends_at) > now;
  return false;
}

async function resetQuotasIfNewMonth(user) {
  const now = new Date();
  const resetDate = new Date(Number(user.quota_reset_date) || 0);
  if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
    const newQuotas = { photo_scans: 0, recipes: 0, programs: 0, coach_messages: 0 };
    const newResetDate = new Date(now.getFullYear(), now.getMonth() + 1, 1).getTime();
    await pool.query(
      'UPDATE users SET quotas_used = $1, quota_reset_date = $2 WHERE email = $3',
      [JSON.stringify(newQuotas), newResetDate, user.email]
    );
    user.quotas_used = newQuotas;
    user.quota_reset_date = newResetDate;
  }
}

function checkQuota(user, type) {
  const used = (user.quotas_used && user.quotas_used[type]) || 0;
  const extra = (user.extra_quotas && user.extra_quotas[type]) || 0;
  const limit = DEFAULT_QUOTAS[type] + extra;
  return { ok: used < limit, used, limit, remaining: Math.max(0, limit - used) };
}

async function consumeQuota(user, type) {
  const newQuotas = { ...user.quotas_used };
  newQuotas[type] = (newQuotas[type] || 0) + 1;
  await pool.query(
    'UPDATE users SET quotas_used = $1 WHERE email = $2',
    [JSON.stringify(newQuotas), user.email]
  );
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    const sessionRes = await pool.query(
      'SELECT s.email, s.expires_at, u.* FROM sessions s JOIN users u ON s.email = u.email WHERE s.token = $1',
      [token]
    );
    if (!sessionRes.rows.length) return res.status(401).json({ error: 'Session expirée — reconnecte-toi' });

    const session = sessionRes.rows[0];
    if (Date.now() > Number(session.expires_at)) {
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
      return res.status(401).json({ error: 'Session expirée — reconnecte-toi' });
    }

    const user = session;
    if (!isSubscriptionActive(user)) {
      return res.status(403).json({
        error: 'Abonnement expiré',
        code: 'SUBSCRIPTION_EXPIRED',
        trial_ended: user.subscription_status === 'trial'
      });
    }

    await resetQuotasIfNewMonth(user);
    req.user = user;
    req.token = token;
    next();
  } catch (e) {
    console.error('authMiddleware error:', e.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
}

// ─── Helper Claude ────────────────────────────────────────────────────────────
function buildFoodAnalysisPrompt(extraContext) {
  const extra = extraContext ? `\n\nINFO SUPPLÉMENTAIRE DE L'UTILISATEUR : "${extraContext}"` : '';
  return `Tu es un expert en nutrition clinique. Analyse cette photo de repas avec PRÉCISION MAXIMALE.

MÉTHODE OBLIGATOIRE — suivre dans cet ordre :
1. Identifier le TYPE de contexte : maison / restaurant / fast-food / traiteur
2. Pour CHAQUE ingrédient visible : estimer le poids en grammes via les repères visuels (assiette 28cm, paume de main = 85g viande, poing fermé = 150g féculents cuits)
3. Calculer les macros de CHAQUE ingrédient séparément (protéines / glucides / lipides / calories)
4. Additionner pour obtenir le total
5. Appliquer les ajustements contextuels (voir ci-dessous)

AJUSTEMENTS CONTEXTUELS OBLIGATOIRES :
- Restaurant / traiteur : +35% sur les lipides (huiles cachées, beurre en cuisson)
- Fast-food : utiliser les calories réelles connues — un Big Mac = 550 kcal, pas 350
- Sauce visible (vinaigrette, mayonnaise, crème) : compter 80-120 kcal par cuillère à soupe
- Fromage fondu ou râpé : minimum 80 kcal pour une poignée standard
- Pain, viennoiserie, pâtes, riz : NE PAS sous-estimer — les féculents visuellement "petits" pèsent souvent 200-300g cuits
- Friture / panure : multiplier les lipides par 2.5 vs la même protéine grillée

VALEURS DE RÉFÉRENCE PRÉCISES (utiliser pour calibrer) :
Protéines :
  Blanc de poulet 100g cuit = 165 kcal / P:31g / G:0g / L:3.5g
  Cuisse poulet 100g cuit = 210 kcal / P:26g / G:0g / L:11g
  Steak bœuf 100g cuit = 250 kcal / P:26g / G:0g / L:16g
  Saumon 100g cuit = 208 kcal / P:20g / G:0g / L:13g
  Thon en boîte 100g égoutté = 116 kcal / P:26g / G:0g / L:1g
  Œuf entier 1 moyen (55g) = 78 kcal / P:6g / G:0g / L:5.5g
  Blanc d'œuf 1 = 17 kcal / P:3.6g / G:0g / L:0g
  Crevettes 100g = 99 kcal / P:21g / G:0g / L:1.4g

Féculents :
  Riz blanc cuit 100g = 130 kcal / P:2.7g / G:28g / L:0.3g
  Riz basmati cuit 100g = 121 kcal / P:2.5g / G:25g / L:0.4g
  Pâtes cuites 100g = 131 kcal / P:5g / G:25g / L:1.1g
  Patate douce cuite 100g = 90 kcal / P:2g / G:21g / L:0.1g
  Pomme de terre cuite 100g = 87 kcal / P:1.9g / G:20g / L:0.1g
  Pain de mie 1 tranche 30g = 80 kcal / P:2.5g / G:15g / L:1g
  Baguette 1 portion 50g = 130 kcal / P:4g / G:25g / L:0.5g
  Quinoa cuit 100g = 120 kcal / P:4.4g / G:21g / L:1.9g

Légumes :
  Légumes verts cuits 100g = 25-35 kcal (compter 30 par défaut)
  Tomate 100g = 18 kcal / P:0.9g / G:3.5g / L:0.2g
  Avocat 100g = 160 kcal / P:2g / G:2g / L:15g

Matières grasses :
  Huile d'olive 10g (1 c.soupe) = 88 kcal / L:10g
  Beurre 10g = 74 kcal / L:8.3g
  Mayonnaise 15g (1 c.soupe) = 103 kcal / L:11g
  Vinaigrette 15g = 67 kcal / L:7g
  Fromage râpé 20g = 80 kcal / P:5g / L:6.5g
  Fromage de chèvre 30g = 80 kcal / P:5g / L:6.4g

RÈGLES ANTI-SOUS-ESTIMATION :
- Une portion de riz dans un restaurant asiatique = 250-350g cuit (pas 100g)
- Une portion de pâtes en restaurant = 200-300g cuit
- Un steak au restaurant = 180-220g minimum
- Si tu hésites entre deux estimations de grammage, prendre la plus haute
- Ne pas oublier la matière grasse de cuisson même si invisible : grillé = +5g huile, sauté = +10-15g, frit = +20-30g${extra}

Réponds UNIQUEMENT en JSON valide sans markdown ni backticks :
{
  "dish_name": "Nom précis du plat",
  "context": "home | restaurant | fast_food | takeaway",
  "confidence": 0.85,
  "needs_clarification": false,
  "clarification_question": null,
  "ingredients_breakdown": [
    {"name": "Blanc de poulet grillé", "estimated_grams": 160, "calories": 264, "protein": 50, "carbs": 0, "fat": 5.6},
    {"name": "Riz blanc cuit", "estimated_grams": 250, "calories": 325, "protein": 6.8, "carbs": 70, "fat": 0.8},
    {"name": "Huile de cuisson estimée", "estimated_grams": 10, "calories": 88, "protein": 0, "carbs": 0, "fat": 10}
  ],
  "macros": {"protein": 57, "carbs": 70, "fat": 16, "calories": 677},
  "meal_type": "lunch",
  "accuracy_note": "Portion restaurant estimée — riz 250g, poulet 160g, huile cuisson incluse"
}`;
}

async function callClaude(route, clientBody) {
  const maxTokens = CLAUDE_CONFIG.max_tokens_by_route[route] || 1000;
  let messages;

  if (route === 'analyze-food' && clientBody.image_base64) {
    messages = [{
      role: 'user',
      content: [
        { type: 'image', source: { type: 'base64', media_type: clientBody.media_type || 'image/jpeg', data: clientBody.image_base64 } },
        { type: 'text', text: buildFoodAnalysisPrompt(clientBody.extra_context || '') }
      ]
    }];
  } else if (clientBody.messages) {
    messages = clientBody.messages.map(m => ({
      role: m.role === 'assistant' ? 'assistant' : 'user',
      content: m.content
    }));
  } else if (clientBody.prompt) {
    messages = [{ role: 'user', content: clientBody.prompt }];
  } else {
    throw new Error('Body invalide — prompt ou messages requis');
  }

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({ model: CLAUDE_CONFIG.model, max_tokens: maxTokens, messages })
  });
  return response.json();
}

// ─── ROUTES HEALTH ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', version: '2.2', service: 'FitForge Backend', db: 'postgresql' });
});

// ─── ROUTES AUTH ─────────────────────────────────────────────────────────────
app.post('/auth/signup', rateLimit(5, 15 * 60 * 1000), async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  if (password.length < 8) return res.status(400).json({ error: 'Mot de passe trop court (8 caractères minimum)' });

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.status(400).json({ error: 'Email invalide' });

  const emailLower = email.toLowerCase().trim();

  try {
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [emailLower]);
    if (existing.rows.length) return res.status(409).json({ error: 'Un compte existe déjà avec cet email' });

    const now = Date.now();
    const trialDays = 7;
    const trialEndsAt = now + (trialDays * 24 * 60 * 60 * 1000);
    const quotaResetDate = new Date(now).setDate(1);

    await pool.query(`
      INSERT INTO users (email, password_hash, created_at, subscription_status, trial_ends_at, quotas_used, extra_quotas, quota_reset_date)
      VALUES ($1, $2, $3, 'trial', $4, $5, $6, $7)
    `, [
      emailLower,
      hashPassword(password),
      now,
      trialEndsAt,
      JSON.stringify({ photo_scans: 0, recipes: 0, programs: 0, coach_messages: 0 }),
      JSON.stringify({ photo_scans: 0, recipes: 0, programs: 0, coach_messages: 0 }),
      quotaResetDate
    ]);

    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      'INSERT INTO sessions (token, email, expires_at) VALUES ($1, $2, $3)',
      [token, emailLower, now + TOKEN_TTL_MS]
    );

    res.json({
      token,
      user: { email: emailLower, subscription_status: 'trial', trial_ends_at: trialEndsAt, trial_days_remaining: trialDays, quotas: DEFAULT_QUOTAS }
    });
  } catch (e) {
    console.error('signup error:', e.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/auth/login', rateLimit(10, 15 * 60 * 1000), async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

  const emailLower = email.toLowerCase().trim();
  const inputHash = hashPassword(password);

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [emailLower]);
    const user = result.rows[0];

    // Timing constant anti-énumération
    const storedHash = user ? user.password_hash : 'dummy_hash_000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';
    const hashBuffer = Buffer.from(inputHash, 'hex');
    const storedBuffer = Buffer.from(storedHash.slice(0, inputHash.length), 'hex');
    const match = user && hashBuffer.length === storedBuffer.length && crypto.timingSafeEqual(hashBuffer, storedBuffer);

    if (!match) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const now = Date.now();
    const token = crypto.randomBytes(32).toString('hex');
    await pool.query(
      'INSERT INTO sessions (token, email, expires_at) VALUES ($1, $2, $3)',
      [token, emailLower, now + TOKEN_TTL_MS]
    );

    const trialDaysRemaining = user.subscription_status === 'trial'
      ? Math.max(0, Math.ceil((Number(user.trial_ends_at) - now) / (24 * 60 * 60 * 1000)))
      : null;

    res.json({
      token,
      user: {
        email: emailLower,
        subscription_status: user.subscription_status,
        trial_ends_at: user.trial_ends_at,
        trial_days_remaining: trialDaysRemaining,
        subscription_ends_at: user.subscription_ends_at,
        plan: user.plan,
        quotas_used: user.quotas_used,
        quotas_limit: DEFAULT_QUOTAS,
        is_active: isSubscriptionActive(user)
      }
    });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/auth/logout', async (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  try { await pool.query('DELETE FROM sessions WHERE token = $1', [token]); } catch(e) {}
  res.json({ ok: true });
});

app.get('/auth/verify', async (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    const result = await pool.query(
      'SELECT s.expires_at, u.* FROM sessions s JOIN users u ON s.email = u.email WHERE s.token = $1',
      [token]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'Session expirée — reconnecte-toi' });

    const user = result.rows[0];
    if (Date.now() > Number(user.expires_at)) {
      await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
      return res.status(401).json({ error: 'Session expirée — reconnecte-toi' });
    }

    await resetQuotasIfNewMonth(user);
    const now = Date.now();
    const active = isSubscriptionActive(user);
    const trialDaysRemaining = user.subscription_status === 'trial'
      ? Math.max(0, Math.ceil((Number(user.trial_ends_at) - now) / (24 * 60 * 60 * 1000)))
      : null;

    res.json({
      valid: true,
      active,
      email: user.email,
      user: {
        email: user.email,
        subscription_status: user.subscription_status,
        trial_ends_at: user.trial_ends_at,
        trial_days_remaining: trialDaysRemaining,
        plan: user.plan,
        quotas_used: user.quotas_used,
        quotas_limit: DEFAULT_QUOTAS
      }
    });
  } catch (e) {
    console.error('verify error:', e.message);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ─── ROUTES STRIPE ────────────────────────────────────────────────────────────
app.post('/stripe/create-checkout', authMiddleware, async (req, res) => {
  if (!STRIPE_SECRET_KEY) return res.status(503).json({ error: 'Stripe non configuré' });
  const { plan } = req.body;
  const priceId = plan === 'annual' ? STRIPE_PRICE_ANNUAL : STRIPE_PRICE_MONTHLY;
  if (!priceId) return res.status(400).json({ error: 'Plan invalide' });

  try {
    const response = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${STRIPE_SECRET_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        'mode': 'subscription',
        'payment_method_types[]': 'card',
        'line_items[0][price]': priceId,
        'line_items[0][quantity]': '1',
        'customer_email': req.user.email,
        'success_url': 'https://escapeai01-boop.github.io/fitforge-app/?payment=success',
        'cancel_url': 'https://escapeai01-boop.github.io/fitforge-app/?payment=cancel',
        'metadata[fitforge_email]': req.user.email
      }).toString()
    });
    const session = await response.json();
    if (session.error) return res.status(400).json({ error: session.error.message });
    res.json({ url: session.url, checkout_url: session.url, session_id: session.id });
  } catch (e) {
    res.status(500).json({ error: 'Erreur création session Stripe' });
  }
});

app.post('/stripe/webhook', async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) return res.status(200).json({ received: true });

  const sig = req.headers['stripe-signature'];
  if (!sig) return res.status(400).json({ error: 'Signature manquante' });

  const payload = req.body.toString('utf8');
  const sigParts = sig.split(',').reduce((acc, part) => { const [k, v] = part.split('='); acc[k] = v; return acc; }, {});
  const { t: timestamp, v1: receivedSig } = sigParts;
  if (!timestamp || !receivedSig) return res.status(400).json({ error: 'Signature invalide' });

  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 300) {
    return res.status(400).json({ error: 'Webhook expiré' });
  }

  const expectedSig = crypto.createHmac('sha256', STRIPE_WEBHOOK_SECRET).update(`${timestamp}.${payload}`).digest('hex');
  const sigBuf = Buffer.from(receivedSig, 'hex');
  const expBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return res.status(400).json({ error: 'Signature invalide' });
  }

  let event;
  try { event = JSON.parse(payload); } catch (e) { return res.status(400).json({ error: 'JSON invalide' }); }

  try {
    if (event.type === 'checkout.session.completed' || event.type === 'invoice.paid') {
      const session = event.data.object;
      const email = session.metadata?.fitforge_email || session.customer_email;
      if (email) {
        const plan = session.metadata?.plan || 'monthly';
        const endsAt = Date.now() + (plan === 'annual' ? 365 : 30) * 24 * 60 * 60 * 1000;
        await pool.query(`
          UPDATE users SET subscription_status='active', plan=$1, stripe_customer_id=$2, subscription_ends_at=$3
          WHERE email=$4
        `, [plan, session.customer, endsAt, email.toLowerCase()]);
        console.log(`Abonnement activé : ${email} (${plan})`);
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      await pool.query(`
        UPDATE users SET subscription_status='cancelled', subscription_ends_at=$1
        WHERE stripe_customer_id=$2
      `, [Date.now(), sub.customer]);
    }
  } catch (e) {
    console.error('Webhook DB error:', e.message);
  }

  res.json({ received: true });
});

// ─── ROUTES CLAUDE ────────────────────────────────────────────────────────────
async function claudeRoute(route, quotaType, req, res) {
  const quota = checkQuota(req.user, quotaType);
  if (!quota.ok) {
    return res.status(429).json({
      error: `Quota ${quotaType} atteint (${quota.used}/${quota.limit} ce mois)`,
      code: 'QUOTA_EXCEEDED',
      quota_type: quotaType,
      used: quota.used,
      limit: quota.limit,
      message: 'Quota mensuel atteint. Réinitialisation le 1er du mois.',
      reset_date: req.user.quota_reset_date
    });
  }

  try {
    const data = await callClaude(route, req.body);
    if (!data.error) await consumeQuota(req.user, quotaType);

    // Pour analyze-food, parser le JSON de la réponse Claude
    if (route === 'analyze-food') {
      const text = data.content && data.content[0] ? data.content[0].text : '';
      try {
        const parsed = JSON.parse(text.replace(/```json?|```/g, '').trim());
        return res.json(parsed);
      } catch(e) {
        return res.json({ text, _raw: true });
      }
    }

    res.json(data);
  } catch (e) {
    console.error(`${route} error:`, e.message);
    res.status(500).json({ error: `Erreur ${route}` });
  }
}

app.post('/analyze-food', authMiddleware, async (req, res) => {
  if (!req.body.image_base64) return res.status(400).json({ error: 'image_base64 requis' });
  await claudeRoute('analyze-food', 'photo_scans', req, res);
});

app.post('/generate-recipe', authMiddleware, (req, res) => claudeRoute('generate-recipe', 'recipes', req, res));
app.post('/generate-program', authMiddleware, (req, res) => claudeRoute('generate-program', 'programs', req, res));
app.post('/coach', authMiddleware, (req, res) => claudeRoute('coach', 'coach_messages', req, res));

app.get('/quotas', authMiddleware, async (req, res) => {
  await resetQuotasIfNewMonth(req.user);
  const quotas = {};
  for (const type of Object.keys(DEFAULT_QUOTAS)) {
    quotas[type] = checkQuota(req.user, type);
  }
  res.json({ quotas, reset_date: req.user.quota_reset_date });
});

// ─── Nettoyage sessions expirées (toutes les 24h) ────────────────────────────
setInterval(async () => {
  try {
    const result = await pool.query('DELETE FROM sessions WHERE expires_at < $1 RETURNING token', [Date.now()]);
    if (result.rowCount > 0) console.log(`Nettoyage : ${result.rowCount} sessions expirées supprimées`);
  } catch(e) { console.error('Cleanup error:', e.message); }
}, 24 * 60 * 60 * 1000);

// ─── Start ────────────────────────────────────────────────────────────────────
async function start() {
  try {
    await initDB();
    app.listen(PORT, () => {
      console.log(`FitForge Backend v2.3 (PostgreSQL) running on port ${PORT}`);
      console.log(`Anthropic API: ${ANTHROPIC_API_KEY ? 'OK' : '❌ MANQUANTE'}`);
      console.log(`Stripe: ${STRIPE_SECRET_KEY ? 'OK' : 'non configuré'}`);
      console.log(`Database: ${process.env.DATABASE_URL ? 'PostgreSQL connecté' : '❌ DATABASE_URL manquante'}`);
    });
  } catch(e) {
    console.error('Erreur démarrage:', e.message);
    process.exit(1);
  }
}

start();
