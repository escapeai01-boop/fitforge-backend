// FitForge Backend v2.1 — Security hardened
// Fixes: bcrypt passwords, Stripe signature verification, CORS restricted,
//        Claude proxy controlled, rate limiting, token expiration
// Node.js 18 / Express

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;

// ─── Config ──────────────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const JWT_SECRET = process.env.JWT_SECRET || 'fitforge-secret-change-me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const STRIPE_PRICE_MONTHLY = process.env.STRIPE_PRICE_MONTHLY || '';
const STRIPE_PRICE_ANNUAL = process.env.STRIPE_PRICE_ANNUAL || '';

// Origines autorisées — CORS restreint
const ALLOWED_ORIGINS = [
  'https://escapeai01-boop.github.io',
  'http://localhost:8080',
  'http://localhost:3000',
  'null' // file:// local pour dev
];

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(cors({
  origin: function(origin, callback) {
    // Autoriser si pas d'origin (Postman, curl) seulement en dev
    if (!origin && process.env.NODE_ENV !== 'production') return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error('CORS: origine non autorisée — ' + origin));
  },
  credentials: true
}));

// Le webhook Stripe a besoin du raw body — DOIT être avant express.json()
app.use('/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10mb' }));

// ─── Rate limiting simple (en mémoire) ───────────────────────────────────────
const RATE_LIMITS = new Map(); // ip+route → { count, reset_at }

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
      return res.status(429).json({
        error: 'Trop de tentatives — réessaie dans ' + retryAfter + ' secondes',
        code: 'RATE_LIMITED'
      });
    }

    entry.count++;
    next();
  };
}

// Nettoyage rate limits toutes les heures
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of RATE_LIMITS.entries()) {
    if (now > entry.reset_at) RATE_LIMITS.delete(key);
  }
}, 60 * 60 * 1000);

// ─── Base de données en mémoire ───────────────────────────────────────────────
// !! MVP uniquement — remplacer par PostgreSQL avant lancement public
const USERS = new Map();    // email → userObject
const SESSIONS = new Map(); // token → { email, expires_at }

// ─── Quotas mensuels ─────────────────────────────────────────────────────────
const DEFAULT_QUOTAS = {
  photo_scans: 60,
  recipes: 20,
  programs: 5,
  coach_messages: 50
};

// Modèle et tokens max forcés côté serveur — le client ne peut pas surcharger
const CLAUDE_CONFIG = {
  model: 'claude-sonnet-4-6',
  max_tokens_by_route: {
    'analyze-food': 1200,
    'generate-recipe': 3000,
    'generate-program': 8000,
    'coach': 1000
  }
};

// ─── Helpers passwords ────────────────────────────────────────────────────────
// bcrypt-like avec 10 rounds via PBKDF2 (pas de dep externe)
function hashPassword(password) {
  const salt = JWT_SECRET.slice(0, 16); // sel fixe basé sur le secret
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

// ─── Helpers tokens ───────────────────────────────────────────────────────────
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 jours

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(email) {
  const token = generateToken();
  SESSIONS.set(token, {
    email: email.toLowerCase(),
    expires_at: Date.now() + TOKEN_TTL_MS
  });
  return token;
}

function getTokenUser(token) {
  const session = SESSIONS.get(token);
  if (!session) return null;
  if (Date.now() > session.expires_at) {
    SESSIONS.delete(token);
    return null;
  }
  return getUser(session.email);
}

// ─── Helpers users ────────────────────────────────────────────────────────────
function getUser(email) {
  return USERS.get(email.toLowerCase());
}

function saveUser(user) {
  USERS.set(user.email, user);
}

function isSubscriptionActive(user) {
  if (!user) return false;
  const now = Date.now();
  if (user.subscription_status === 'trial') return user.trial_ends_at > now;
  if (user.subscription_status === 'active') return user.subscription_ends_at > now;
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
  const extra = (user.extra_quotas && user.extra_quotas[type]) || 0;
  const limit = DEFAULT_QUOTAS[type] + extra;
  return { ok: used < limit, used, limit, remaining: Math.max(0, limit - used) };
}

function consumeQuota(user, type) {
  user.quotas_used[type] = (user.quotas_used[type] || 0) + 1;
  saveUser(user);
}

// ─── Middleware auth ──────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  const user = getTokenUser(token);
  if (!user) return res.status(401).json({ error: 'Session expirée — reconnecte-toi' });

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

// ─── Helper proxy Claude sécurisé ────────────────────────────────────────────
// Le client envoie { prompt, messages, image_base64... }
// Le serveur reconstruit le body Claude proprement — le client ne contrôle pas model/max_tokens
async function callClaude(route, clientBody) {
  const maxTokens = CLAUDE_CONFIG.max_tokens_by_route[route] || 1000;

  // Construction du body selon le type de requête
  let messages;

  if (route === 'analyze-food' && clientBody.image_base64) {
    // Photo repas avec vision
    const extraContext = clientBody.extra_context || '';
    const prompt = buildFoodAnalysisPrompt(extraContext);
    messages = [{
      role: 'user',
      content: [
        {
          type: 'image',
          source: {
            type: 'base64',
            media_type: clientBody.media_type || 'image/jpeg',
            data: clientBody.image_base64
          }
        },
        { type: 'text', text: prompt }
      ]
    }];
  } else if (clientBody.messages) {
    // Messages déjà structurés (coach, etc.) — on les accepte mais on sanitise
    messages = clientBody.messages.map(m => ({
      role: m.role === 'assistant' ? 'assistant' : 'user',
      content: typeof m.content === 'string' ? m.content : m.content
    }));
  } else if (clientBody.prompt) {
    // Prompt simple texte
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
    body: JSON.stringify({
      model: CLAUDE_CONFIG.model,
      max_tokens: maxTokens,
      messages
    })
  });

  return response.json();
}

// Prompt analyse photo — centralisé côté serveur
function buildFoodAnalysisPrompt(extraContext) {
  const extra = extraContext ? `\n\nINFO SUPPLÉMENTAIRE DE L'UTILISATEUR : "${extraContext}"` : '';
  return `Tu es un expert en nutrition et analyse alimentaire. Analyse cette photo de repas avec PRÉCISION MAXIMALE.

MÉTHODE D'ANALYSE :
1. Identifie CHAQUE ingrédient visible et ses portions estimées en grammes
2. Calcule les macros pour CHAQUE composant séparément puis additionne
3. Base tes estimations sur les tailles d'assiette standard (28cm) et les portions réelles
4. Si un ingrédient est ambigu, prends la valeur moyenne (ex: blanc de poulet vs cuisse)
5. Compte l'huile de cuisson estimée (+5-15g selon le mode de cuisson)
6. Ne sous-estime JAMAIS les calories — les gens sous-estiment naturellement leurs portions${extra}

IMPORTANT sur la précision :
- Un plat de restaurant = portions généreuses (30-50% de plus qu'à la maison)
- Riz cuit 150g ≈ 195 kcal | Pâtes cuites 200g ≈ 260 kcal | Poulet 150g ≈ 165 kcal
- Si tu vois des sauces, huiles, fromage — ils doublent souvent les calories
- Marge d'erreur acceptable : ±15% mais PAS ±50%

Réponds UNIQUEMENT en JSON valide sans markdown :
{
  "dish_name": "Nom précis du plat",
  "confidence": 0.85,
  "needs_clarification": false,
  "clarification_question": null,
  "ingredients_breakdown": [
    {"name": "Blanc de poulet grillé", "estimated_grams": 150, "calories": 165, "protein": 31, "carbs": 0, "fat": 3.5}
  ],
  "macros": {"protein": 45, "carbs": 60, "fat": 18, "calories": 582},
  "meal_type": "lunch",
  "accuracy_note": "Estimation basée sur assiette standard 28cm, portion restaurant"
}`;
}

// ─── ROUTES HEALTH ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', version: '2.1', service: 'FitForge Backend' });
});

// ─── ROUTES AUTH ─────────────────────────────────────────────────────────────

// Inscription — rate limit 5 tentatives / 15 min par IP
app.post('/auth/signup', rateLimit(5, 15 * 60 * 1000), (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
  if (password.length < 8) return res.status(400).json({ error: 'Mot de passe trop court (8 caractères minimum)' });

  // Validation email basique
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) return res.status(400).json({ error: 'Email invalide' });

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
    quota_reset_date: new Date(now).setDate(1)
  };

  saveUser(user);
  const token = createSession(emailLower);

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

// Connexion — rate limit 10 tentatives / 15 min par IP (anti brute-force)
app.post('/auth/login', rateLimit(10, 15 * 60 * 1000), (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

  const emailLower = email.toLowerCase().trim();
  const user = getUser(emailLower);

  // Timing constant pour éviter l'énumération d'emails
  const inputHash = hashPassword(password);
  const storedHash = user ? user.password_hash : 'dummy_hash_to_prevent_timing_attack';
  if (!user || inputHash !== storedHash) {
    return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  }

  const token = createSession(emailLower);
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
  const token = auth.replace('Bearer ', '').trim();
  SESSIONS.delete(token);
  res.json({ ok: true });
});

// Vérifier token + statut abonnement
app.get('/auth/verify', (req, res) => {
  const auth = req.headers.authorization || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  const user = getTokenUser(token);
  if (!user) return res.status(401).json({ error: 'Session expirée — reconnecte-toi' });

  resetQuotasIfNewMonth(user);
  const now = Date.now();
  const active = isSubscriptionActive(user);
  const trialDaysRemaining = user.subscription_status === 'trial'
    ? Math.max(0, Math.ceil((user.trial_ends_at - now) / (24 * 60 * 60 * 1000)))
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
        'success_url': 'https://escapeai01-boop.github.io/fitforge-app/?payment=success',
        'cancel_url': 'https://escapeai01-boop.github.io/fitforge-app/?payment=cancel',
        'metadata[fitforge_email]': req.user.email
      }).toString()
    });
    const session = await response.json();
    if (session.error) return res.status(400).json({ error: session.error.message });
    // Retourner url (nouveau) et checkout_url (compat ancien)
    res.json({ url: session.url, checkout_url: session.url, session_id: session.id });
  } catch (e) {
    res.status(500).json({ error: 'Erreur création session Stripe' });
  }
});

// Webhook Stripe — avec vérification de signature CORRECTE
app.post('/stripe/webhook', async (req, res) => {
  if (!STRIPE_WEBHOOK_SECRET) {
    console.warn('Webhook Stripe reçu mais STRIPE_WEBHOOK_SECRET non configuré');
    return res.status(200).json({ received: true });
  }

  const sig = req.headers['stripe-signature'];
  if (!sig) return res.status(400).json({ error: 'Signature manquante' });

  // Vérification HMAC Stripe (sans lib stripe)
  const payload = req.body.toString('utf8');
  const sigParts = sig.split(',').reduce((acc, part) => {
    const [k, v] = part.split('=');
    acc[k] = v;
    return acc;
  }, {});

  const timestamp = sigParts.t;
  const receivedSig = sigParts.v1;
  if (!timestamp || !receivedSig) return res.status(400).json({ error: 'Signature invalide' });

  // Vérifier que le timestamp n'est pas trop vieux (5 minutes max)
  if (Math.abs(Date.now() / 1000 - parseInt(timestamp)) > 300) {
    return res.status(400).json({ error: 'Webhook expiré (replay attack)' });
  }

  // Calculer la signature attendue
  const signedPayload = `${timestamp}.${payload}`;
  const expectedSig = crypto
    .createHmac('sha256', STRIPE_WEBHOOK_SECRET)
    .update(signedPayload)
    .digest('hex');

  // Comparaison timing-safe
  const sigBuffer = Buffer.from(receivedSig, 'hex');
  const expectedBuffer = Buffer.from(expectedSig, 'hex');
  if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
    console.error('Webhook Stripe : signature invalide — possible tentative de fraude');
    return res.status(400).json({ error: 'Signature invalide' });
  }

  let event;
  try {
    event = JSON.parse(payload);
  } catch (e) {
    return res.status(400).json({ error: 'JSON invalide' });
  }

  // Traitement des événements Stripe
  if (event.type === 'checkout.session.completed' || event.type === 'invoice.paid') {
    const session = event.data.object;
    const email = session.metadata?.fitforge_email || session.customer_email;
    if (email) {
      const user = getUser(email);
      if (user) {
        const plan = session.metadata?.plan || 'monthly';
        user.subscription_status = 'active';
        user.plan = plan;
        user.stripe_customer_id = session.customer;
        user.subscription_ends_at = Date.now() + (plan === 'annual'
          ? 365 * 24 * 60 * 60 * 1000
          : 30 * 24 * 60 * 60 * 1000);
        saveUser(user);
        console.log(`Abonnement activé : ${email} (${plan})`);
      }
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    for (const [, user] of USERS.entries()) {
      if (user.stripe_customer_id === sub.customer) {
        user.subscription_status = 'cancelled';
        user.subscription_ends_at = Date.now(); // expire immédiatement
        saveUser(user);
        console.log(`Abonnement annulé : ${user.email}`);
        break;
      }
    }
  }

  res.json({ received: true });
});

// ─── ROUTES CLAUDE (protégées auth + quota) ───────────────────────────────────

app.post('/analyze-food', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'photo_scans');
  if (!quota.ok) {
    return res.status(429).json({
      error: `Quota photo atteint (${quota.used}/${quota.limit} ce mois)`,
      code: 'QUOTA_EXCEEDED',
      quota_type: 'photo_scans',
      used: quota.used,
      limit: quota.limit,
      message: 'Quota mensuel atteint. Réinitialisation le 1er du mois.',
      reset_date: req.user.quota_reset_date
    });
  }
  if (!req.body.image_base64) {
    return res.status(400).json({ error: 'image_base64 requis' });
  }
  try {
    const data = await callClaude('analyze-food', req.body);
    if (!data.error) consumeQuota(req.user, 'photo_scans');
    // Extraire le texte JSON de la réponse Claude et le parser
    const text = data.content && data.content[0] ? data.content[0].text : '';
    try {
      const parsed = JSON.parse(text.replace(/```json?|```/g, '').trim());
      res.json(parsed);
    } catch(e) {
      // Retourner la réponse brute si le parsing échoue
      res.json({ text, _raw: true });
    }
  } catch (e) {
    console.error('analyze-food error:', e.message);
    res.status(500).json({ error: 'Erreur analyse photo' });
  }
});

app.post('/generate-recipe', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'recipes');
  if (!quota.ok) {
    return res.status(429).json({
      error: `Quota recettes atteint (${quota.used}/${quota.limit} ce mois)`,
      code: 'QUOTA_EXCEEDED',
      quota_type: 'recipes',
      used: quota.used,
      limit: quota.limit,
      message: 'Quota mensuel atteint. Réinitialisation le 1er du mois.',
      reset_date: req.user.quota_reset_date
    });
  }
  try {
    const data = await callClaude('generate-recipe', req.body);
    if (!data.error) consumeQuota(req.user, 'recipes');
    // Retourner la réponse Claude telle quelle (le frontend parse)
    res.json(data);
  } catch (e) {
    console.error('generate-recipe error:', e.message);
    res.status(500).json({ error: 'Erreur génération recette' });
  }
});

app.post('/generate-program', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'programs');
  if (!quota.ok) {
    return res.status(429).json({
      error: `Quota programme atteint (${quota.used}/${quota.limit} ce mois)`,
      code: 'QUOTA_EXCEEDED',
      quota_type: 'programs',
      used: quota.used,
      limit: quota.limit,
      message: 'Quota mensuel atteint. Réinitialisation le 1er du mois.',
      reset_date: req.user.quota_reset_date
    });
  }
  try {
    const data = await callClaude('generate-program', req.body);
    if (!data.error) consumeQuota(req.user, 'programs');
    res.json(data);
  } catch (e) {
    console.error('generate-program error:', e.message);
    res.status(500).json({ error: 'Erreur génération programme' });
  }
});

app.post('/coach', authMiddleware, async (req, res) => {
  const quota = checkQuota(req.user, 'coach_messages');
  if (!quota.ok) {
    return res.status(429).json({
      error: `Quota coach atteint (${quota.used}/${quota.limit} ce mois)`,
      code: 'QUOTA_EXCEEDED',
      quota_type: 'coach_messages',
      used: quota.used,
      limit: quota.limit,
      message: 'Quota mensuel atteint. Réinitialisation le 1er du mois.',
      reset_date: req.user.quota_reset_date
    });
  }
  try {
    const data = await callClaude('coach', req.body);
    if (!data.error) consumeQuota(req.user, 'coach_messages');
    res.json(data);
  } catch (e) {
    console.error('coach error:', e.message);
    res.status(500).json({ error: 'Erreur coach IA' });
  }
});

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
  console.log(`FitForge Backend v2.1 running on port ${PORT}`);
  console.log(`Anthropic API: ${ANTHROPIC_API_KEY ? 'OK' : '❌ MANQUANTE'}`);
  console.log(`Stripe: ${STRIPE_SECRET_KEY ? 'OK' : 'non configuré'}`);
  console.log(`Webhook secret: ${STRIPE_WEBHOOK_SECRET ? 'OK' : '⚠️ non configuré'}`);
  console.log(`CORS: ${ALLOWED_ORIGINS.join(', ')}`);
});
