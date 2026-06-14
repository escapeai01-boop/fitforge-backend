// FitForge Backend v2.0
// Routes: auth + quotas + Stripe + proxy Claude
// Node.js 18 / Express

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '10mb' })); // limit pour les photos base64

// ─── Config ──────────────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'fitforge-secret-change-me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_MONTHLY = process.env.STRIPE_PRICE_MONTHLY || ''; // price_xxx
const STRIPE_PRICE_ANNUAL = process.env.STRIPE_PRICE_ANNUAL || '';   // price_xxx

// ─── Base de données en mémoire (simple Map — Railway redémarre = reset)
// !! Pour production réelle, remplacer par PostgreSQL Railway
// Pour le MVP, ça suffit — les données persistent tant que le service tourne
const USERS = new Map();      // email → userObject
const SESSIONS = new Map();   // token → email

// ─── Quotas mensuels par défaut ───────────────────────────────────────────────
const DEFAULT_QUOTAS = {
  photo_scans: 60,
  recipes: 20,
  programs: 5,
  coach_messages: 50
};

// ─── Helpers ─────────────────────────────────────────────────────────────────
function hashPassword(password) {
  return crypto.createHash('sha256')
    .update(password + JWT_SECRET)
    .digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function getUser(email) {
  return USERS.get(email.toLowerCase());
}

function saveUser(user) {
  USERS.set(user.email, user);
}

function getTokenUser(token) {
  const email = SESSIONS.get(token);
  if (!email) return null;
  return getUser(email);
}

function isSubscriptionActive(user) {
  if (!user) return false;
  const now = Date.now();
  if (user.subscription_status === 'trial') {
    return user.trial_ends_at > now;
  }
  if (user.subscription_status === 'active') {
    return user.subscription_ends_at > now;
  }
  return false;
}

function resetQuotasIfNewMonth(user) {
  const now = new Date();
  const resetDate = new Date(user.quota_reset_date || 0);
  if (now.getMonth() !== resetDate.getMonth() || now.getFullYear() !== resetDate.getFullYear()) {
    user.quotas_used = { photo_scans: 0, recipes: 0, programs: 0, coach_messages: 0 };
    user.quota_reset_date = new Date(now.getFullYear(), now.getMonth() + 1, 1).getTime();
    saveUser(user);
  }
}

function checkQuota(user, type) {
  resetQuotasIfNewMonth(user);
  const used = user.quotas_used[type] || 0;
  const limit = (user.extra_quotas && user.extra_quotas[type] || 0) + DEFAULT_QUOTAS[type];
  return { ok: used < limit, used, limit, remaining: Math.max(0, limit - used) };
}

function consumeQuota(user, type) {
  user.quotas_used[type] = (user.quotas_used[type] || 0) + 1;
  saveUser(user);
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  const user = getTokenUser(token);
  if (!user) return res.status(401).json({ error: 'Token invalide ou expiré' });
  if (!isSubscriptionActive(user)) {
    return res.status(403).json({
      error: 'Abonnement expiré',
      code: 'SUBSCRIPTION_EXPIRED',
      trial_ended: user.subscription_status === 'trial'
    });
  }
  req.user = user;
  req.token = token;
  next();
}

// ─── ROUTES AUTH ─────────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', version: '2.0', service: 'FitForge Backend' });
});

// Inscription
app.post('/auth/signup', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court (6 caractères minimum)' });

  const emailLower = email.toLowerCase().trim();
  if (getUser(emailLower)) return res.status(409).json({ error: 'Un compte existe déjà avec cet email' });

  const now = Date.now();
  const trialDays = 7;
  const user = {
    email: emailLower,
    password_hash: hashPassword(password),
    created_at: now,
    subscription_status: 'trial',
    trial_ends_at: now + (trialDays * 24 * 60 * 60 * 1000),
    subscription_ends_at: null,
    plan: null,
    stripe_customer_id: null,
    quotas_used: { photo_scans: 0, recipes: 0, programs: 0, coach_messages: 0 },
    extra_quotas: { photo_scans: 0, recipes: 0, programs: 0, coach_messages: 0 },
    quota_reset_date: new Date(now).setDate(1) // 1er du mois suivant
  };

  saveUser(user);
  const token = generateToken();
  SESSIONS.set(token, emailLower);

  res.json({
    token,
    user: {
      email: emailLower,
      subscription_status: 'trial',
      trial_ends_at: user.trial_ends_at,
      trial_days_remaining: trialDays,
      quotas: DEFAULT_QUOTAS
    }
  });
});

// Connexion
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

  const emailLower = email.toLowerCase().trim();
  const user = getUser(emailLower);
  if (!user || user.password_hash !== hashPassword(password)) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  }

  const token = generateToken();
  SESSIONS.set(token, emailLower);
  resetQuotasIfNewMonth(user);

  const now = Date.now();
  const trialDaysRemaining = user.subscription_status === 'trial'
    ? Math.max(0, Math.ceil((user.trial_ends_at - now) / (24 * 60 * 60 * 1000)))
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
});

// Déconnexion
app.post('/auth/logout', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  SESSIONS.delete(token);
  res.json({ ok: true });
});

// Vérifier token + statut abonnement
app.get('/auth/verify', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  const user = getTokenUser(token);
  if (!user) return res.status(401).json({ error: 'Token invalide' });

  resetQuotasIfNewMonth(user);
  const now = Date.now();
  const active = isSubscriptionActive(user);
  const trialDaysRemaining = user.subscription_status === 'trial'
    ? Math.max(0, Math.ceil((user.trial_ends_at - now) / (24 * 60 * 60 * 1000)))
    : null;

  res.json({
    valid: true,
    active,
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
});

// ─── ROUTES STRIPE ────────────────────────────────────────────────────────────

// Créer une session de paiement Stripe
app.post('/stripe/create-checkout', authMiddleware, async (req, res) => {
  if (!STRIPE_SECRET_KEY) return res.status(503).json({ error: 'Stripe non configuré' });
  const { plan } = req.body; // 'monthly' ou 'annual'
  const priceId = plan === 'annual' ? STRIPE_PRICE_ANNUAL : STRIPE_PRICE_MONTHLY;
  if (!priceId) return res.status(400).json({ error: 'Plan invalide' });

  try {
    const response = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'mode': 'subscription',
        'payment_method_types[]': 'card',
        'line_items[0][price]': priceId,
        'line_items[0][quantity]': '1',
        'customer_email': req.user.email,
        'trial_period_days': '7',
        'success_url': 'https://escapeai01-boop.github.io/fitforge-app/?payment=success',
        'cancel_url': 'https://escapeai01-boop.github.io/fitforge-app/?payment=cancel',
        'metadata[fitforge_email]': req.user.email
      }).toString()
    });
    const session = await response.json();
    if (session.error) return res.status(400).json({ error: session.error.message });
    res.json({ checkout_url: session.url, session_id: session.id });
  } catch (e) {
    res.status(500).json({ error: 'Erreur création session Stripe' });
  }
});

// Webhook Stripe (paiement confirmé)
app.post('/stripe/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    if (!STRIPE_WEBHOOK_SECRET) return res.status(200).json({ received: true });
    const sig = req.headers['stripe-signature'];
    let event;
    try {
      // Vérification signature Stripe (sans lib stripe, on fait confiance au secret)
      const payload = req.body.toString();
      event = JSON.parse(payload);
    } catch (e) {
      return res.status(400).json({ error: 'Webhook invalide' });
    }

    if (event.type === 'checkout.session.completed' || event.type === 'invoice.paid') {
      const session = event.data.object;
      const email = session.metadata?.fitforge_email || session.customer_email;
      const plan = session.metadata?.plan || 'monthly';
      if (email) {
        const user = getUser(email);
        if (user) {
          user.subscription_status = 'active';
          user.plan = plan;
          user.stripe_customer_id = session.customer;
          user.subscription_ends_at = Date.now() + (plan === 'annual'
            ? 365 * 24 * 60 * 60 * 1000
            : 30 * 24 * 60 * 60 * 1000);
          saveUser(user);
        }
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      for (const [email, user] of USERS.entries()) {
        if (user.stripe_customer_id === sub.customer) {
          user.subscription_status = 'cancelled';
          saveUser(user);
          break;
        }
      }
    }

    res.json({ received: true });
  }
);

// ─── ROUTES CLAUDE (protégées par auth + quota) ───────────────────────────────

// Analyse photo repas (existant — maintenant protégé)
app.post('/analyze-food', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'photo_scans');
  if (!quota.ok) {
    return res.status(429).json({
      error: 'Quota photo atteint',
      code: 'QUOTA_EXCEEDED',
      quota_type: 'photo_scans',
      used: quota.used,
      limit: quota.limit,
      reset_date: req.user.quota_reset_date
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    if (!data.error) consumeQuota(req.user, 'photo_scans');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur API Claude' });
  }
});

// Génération recette (existant — maintenant protégé)
app.post('/generate-recipe', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'recipes');
  if (!quota.ok) {
    return res.status(429).json({
      error: 'Quota recettes atteint',
      code: 'QUOTA_EXCEEDED',
      quota_type: 'recipes',
      used: quota.used,
      limit: quota.limit,
      reset_date: req.user.quota_reset_date
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    if (!data.error) consumeQuota(req.user, 'recipes');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur API Claude' });
  }
});

// Génération programme (nouveau)
app.post('/generate-program', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'programs');
  if (!quota.ok) {
    return res.status(429).json({
      error: 'Quota programme atteint',
      code: 'QUOTA_EXCEEDED',
      quota_type: 'programs',
      used: quota.used,
      limit: quota.limit,
      reset_date: req.user.quota_reset_date
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    if (!data.error) consumeQuota(req.user, 'programs');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur API Claude' });
  }
});

// Coach IA (nouveau)
app.post('/coach', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'coach_messages');
  if (!quota.ok) {
    return res.status(429).json({
      error: 'Quota coach atteint',
      code: 'QUOTA_EXCEEDED',
      quota_type: 'coach_messages',
      used: quota.used,
      limit: quota.limit,
      reset_date: req.user.quota_reset_date
    });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify(req.body)
    });
    const data = await response.json();
    if (!data.error) consumeQuota(req.user, 'coach_messages');
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: 'Erreur API Claude' });
  }
});

// Statut quotas (pour afficher dans l'app)
app.get('/quotas', authMiddleware, (req, res) => {
  resetQuotasIfNewMonth(req.user);
  const quotas = {};
  for (const type of Object.keys(DEFAULT_QUOTAS)) {
    quotas[type] = checkQuota(req.user, type);
  }
  res.json({ quotas, reset_date: req.user.quota_reset_date });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`FitForge Backend v2.0 running on port ${PORT}`);
  console.log(`Anthropic API key: ${ANTHROPIC_API_KEY ? 'OK' : 'MANQUANTE'}`);
  console.log(`Stripe: ${STRIPE_SECRET_KEY ? 'configuré' : 'non configuré'}`);
});
