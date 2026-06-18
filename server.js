// FitForge Backend v2.9 — Analyse photo internationale (street food, cuisine mondiale)
// v2.3 : Prompt analyze-food renforcé (valeurs nutritionnelles de référence)
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
    // Autoriser : pas d'origin, origin 'null' (file://), ou origine connue
    if (!origin || origin === 'null' || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
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
    'analyze-food': 2000,
    'generate-recipe': 12000,
    'generate-program': 8000,
    'coach': 1500
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
  // Compte dev ou admin — quotas illimités
  if (user.email === 'dev@fitforge.internal' || user.plan === 'dev') {
    return { allowed: true, ok: true, used: 0, limit: 999999, remaining: 999999 };
  }
  const used = (user.quotas_used && user.quotas_used[type]) || 0;
  const extra = (user.extra_quotas && user.extra_quotas[type]) || 0;
  const limit = DEFAULT_QUOTAS[type] + extra;
  return { allowed: used < limit, ok: used < limit, used, limit, remaining: Math.max(0, limit - used) };
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
  const extra = extraContext
    ? `\n\n═══ INFORMATION PRIORITAIRE DE L'UTILISATEUR ═══
L'utilisateur a indiqué : "${extraContext}"
→ UTILISER CETTE INFORMATION EN PRIORITÉ ABSOLUE sur ta reconnaissance visuelle.
→ Si c'est un nom de plat : baser toute la composition sur ce plat spécifique (ingrédients typiques de la recette).
→ Si c'est une description partielle : l'utiliser pour affiner l'estimation visuelle.
→ dish_name DOIT refléter cette information.`
    : '';
  return `Tu es un expert en nutrition avec une connaissance encyclopédique de la cuisine mondiale — street food asiatique, cuisine africaine, plats latino-américains, fast-food international, snacks de rue, etc. Tu peux identifier et analyser n'importe quel plat, qu'il soit servi dans une assiette de restaurant ou tenu à la main dans la rue.

═══ ÉTAPE 1 — IDENTIFICATION ═══
Identifier :
a) Le plat ou les aliments (nom précis, origine culturelle si pertinente)
b) Le contexte de consommation : street_food | restaurant | fast_food | takeaway | home | cafe | market_stall
c) Le mode de cuisson dominant : frit / grillé / vapeur / cru / mijoté / sauté

Pour les plats inconnus ou inhabituels : raisonner depuis la composition probable (viande/féculent/sauce/légume) et les techniques de cuisson visibles. Ne jamais abandonner — toujours donner une estimation même sur un plat non identifié.

═══ ÉTAPE 2 — DÉCOMPOSITION VISUELLE ═══
Repères de calibration visuelle :
- Paume de main = 85-100g de viande / poisson cuit
- Poing fermé = 150-200g de féculent cuit ou légume
- Pouce = 15-20g de matière grasse (beurre, sauce épaisse)
- Assiette standard 28cm de diamètre comme référence
- Brochette de street food = 80-150g selon taille
- Barquette takeaway standard = 300-450g de contenu
- Bol ramen / pho = 500-700g total liquide inclus
- Portion burger fast-food = 250-400g total pain inclus

Décomposer CHAQUE élément visible séparément, même les petits (sauce, garniture, huile de cuisson estimée).

═══ ÉTAPE 3 — CALCUL MACROS PAR INGRÉDIENT ═══
Utiliser ces valeurs de référence pour les aliments courants, extrapoler pour les équivalents mondiaux :

PROTÉINES (pour 100g cuit) :
  Volaille grillée (poulet, canard, dinde) : 165-210 kcal / P:26-31g / L:3-11g / G:0g
  Porc grillé ou rôti : 242 kcal / P:27g / L:14g / G:0g
  Bœuf grillé : 250 kcal / P:26g / L:16g / G:0g
  Agneau grillé : 258 kcal / P:25g / L:17g / G:0g
  Poisson blanc grillé (cabillaud, tilapia, bar) : 105 kcal / P:23g / L:1g / G:0g
  Poisson gras grillé (saumon, maquereau, sardine) : 200-250 kcal / P:20-22g / L:13-17g / G:0g
  Crevettes / fruits de mer : 99 kcal / P:21g / L:1.4g / G:0g
  Tofu ferme 100g : 76 kcal / P:8g / L:4.5g / G:1.9g
  Œuf entier 1 moyen : 78 kcal / P:6g / L:5.5g / G:0g
  Légumineuses cuites 100g (lentilles, pois chiches, haricots) : 110-130 kcal / P:7-9g / L:0.5g / G:18-22g
  FRITURE : multiplier les lipides par 2.5 et ajouter 15-25g de lipides pour la panure/huile absorbée

FÉCULENTS (pour 100g cuit) :
  Riz blanc / jasmin / gluant : 130 kcal / P:2.7g / G:28g / L:0.3g
  Nouilles de riz cuites : 108 kcal / P:2g / G:25g / L:0.2g
  Nouilles soba cuites : 99 kcal / P:5g / G:21g / L:0.1g
  Nouilles ramen / egg noodles cuites : 138 kcal / P:5g / G:25g / L:2g
  Pâtes cuites : 131 kcal / P:5g / G:25g / L:1.1g
  Pain plat (naan, pita, tortilla) 1 pièce 60-80g : 180-220 kcal / P:6g / G:34g / L:3g
  Patate douce cuite 100g : 90 kcal / P:2g / G:21g / L:0.1g
  Pomme de terre cuite 100g : 87 kcal / P:1.9g / G:20g / L:0.1g
  Frites 100g : 312 kcal / P:3.4g / G:41g / L:15g
  Manioc / taro / igname cuit 100g : 112-120 kcal / P:1.5g / G:27g / L:0.2g

SAUCES ET ACCOMPAGNEMENTS (estimer la quantité visible) :
  Sauce soja 15ml (1 c.soupe) : 9 kcal / P:1.3g / G:0.8g / L:0g
  Sauce huître 15ml : 29 kcal / G:7g
  Sauce cacahuète 30g (2 c.soupe) : 188 kcal / P:8g / G:7g / L:16g
  Curry / sauce cocotte avec lait de coco : 150-200 kcal pour 100ml
  Hummus 30g : 83 kcal / P:3g / G:6g / L:5.5g
  Guacamole 30g : 48 kcal / P:0.6g / G:2.5g / L:4.5g
  Sauce chili douce 15ml : 23 kcal / G:5.5g
  Tahini 15g : 89 kcal / P:3g / G:3g / L:8g
  Mayonnaise / aioli 15g : 103 kcal / L:11g
  Crème fraîche / sour cream 30g : 58 kcal / L:6g

MATIÈRES GRASSES ET CUISSON :
  Huile (toutes) 10g : 88 kcal / L:10g
  Beurre 10g : 74 kcal / L:8.3g
  Huile de cuisson invisible : grillé +5g, sauté +10g, wok +15g, frit +20-30g
  Lait de coco 100ml : 197 kcal / L:21g / G:3g

DESSERTS ET PÂTISSERIES OCCIDENTAUX :
  Boule de glace standard 80g (vanille, chocolat, fraise) : 150-180 kcal / G:20g / L:8g / P:2g
  Bâtonnet glacé enrobé chocolat (Magnum style) : 250-280 kcal / G:23g / L:17g
  Sorbet 1 boule 80g : 80-100 kcal / G:22g / L:0g
  Glace soft-serve cornet : 220-280 kcal / G:38g / L:8g
  Chantilly 30g : 93 kcal / L:9g / G:2.5g
  Gaufre nature 100g : 291 kcal / G:43g / L:11g / P:7g
  Crêpe nature 60g : 130 kcal / G:18g / L:5g / P:4g
  Pancake 60g : 175 kcal / G:26g / L:5g / P:5g
  Brownie 60g : 243 kcal / G:32g / L:12g / P:3g
  Fondant / moelleux chocolat 80g : 310 kcal / G:38g / L:16g / P:5g
  Muffin standard 100g : 375 kcal / G:51g / L:17g / P:5g
  Croissant 60g : 231 kcal / G:26g / L:12g / P:4.5g
  Pain au chocolat 80g : 330 kcal / G:40g / L:16g / P:6g
  Éclair chocolat 100g : 290 kcal / G:35g / L:14g / P:5g
  Millefeuille 1 part 100g : 395 kcal / G:45g / L:22g / P:5g
  Tarte aux pommes 1 part 120g : 280 kcal / G:38g / L:13g / P:3g
  Tarte au citron meringuée 1 part 120g : 320 kcal / G:46g / L:13g / P:4g
  Cheesecake 1 part 120g : 370 kcal / G:33g / L:23g / P:7g
  Tiramisu 1 part 120g : 290 kcal / G:27g / L:17g / P:6g
  Panna cotta 100g : 200 kcal / G:18g / L:13g / P:3g
  Mousse au chocolat 100g : 285 kcal / G:26g / L:18g / P:5g
  Crème brûlée 120g : 280 kcal / G:25g / L:17g / P:5g
  Île flottante 150g : 190 kcal / G:28g / L:6g / P:7g
  Profiteroles 3 pièces 100g : 350 kcal / G:32g / L:21g / P:6g
  Baba au rhum 80g : 220 kcal / G:35g / L:5g / P:4g
  Cannelé 50g : 172 kcal / G:30g / L:4.5g / P:3g
  Macaron 1 pièce 15g : 65 kcal / G:9g / L:3g / P:1g
  Cookie 40g : 185 kcal / G:25g / L:9g / P:2.5g
  Financier 30g : 130 kcal / G:14g / L:7.5g / P:2.5g
  Donut glacé 60g : 253 kcal / G:31g / L:13g / P:3g
  Beignet sucré 50g : 210 kcal / G:26g / L:10g / P:3g
  Churros 100g avec sucre : 364 kcal / G:43g / L:19g / P:6g
  Brownie blondie 60g : 255 kcal / G:33g / L:12g / P:3g
  Carrot cake 1 part 100g : 415 kcal / G:52g / L:21g / P:4g
  Red velvet cake 1 part 100g : 380 kcal / G:50g / L:18g / P:4g
  Banana bread 1 tranche 60g : 196 kcal / G:32g / L:6g / P:3.5g
  Chips 30g : 160 kcal / G:15g / L:10g
  Barre chocolatée 50g (Snickers/Mars/KitKat) : 230-250 kcal / G:30-35g / L:10-13g / P:4g
  Nutella 20g (1 c.soupe) : 118 kcal / G:13g / L:7g / P:1.5g
  Bonbons gélifiés 30g : 105 kcal / G:26g / L:0g
  Sucette standard 12g : 45 kcal / G:11g
  Réglisse 30g : 100 kcal / G:23g / L:0.5g
  Guimauve 1 pièce 7g : 23 kcal / G:6g
  Caramel bonbon 10g : 39 kcal / G:8g / L:1g
  Nougat 30g : 115 kcal / G:22g / L:2.5g / P:1.5g

DESSERTS ET SUCRERIES ASIATIQUES :
  Mochi 1 pièce 45g : 100 kcal / G:22g / L:1g / P:1.5g
  Daifuku 1 pièce 50g : 120 kcal / G:26g / L:1g / P:2g
  Taiyaki 1 pièce 80g : 200 kcal / G:38g / L:3.5g / P:4.5g
  Dorayaki 1 pièce 80g : 230 kcal / G:44g / L:4g / P:5g
  Anmitsu 1 bol 200g : 180 kcal / G:40g / L:1g / P:3g
  Kakigori (glace pilée siropée) 200g : 120-180 kcal / G:30-45g / L:0g
  Bingsu coréen 300g : 280-400 kcal / G:65-90g / L:3-8g
  Matcha ice cream 1 boule 80g : 160 kcal / G:20g / L:8g / P:3g
  Sesame balls (jian dui) 1 pièce 50g : 150 kcal / G:22g / L:6g / P:3g
  Tang yuan 3 pièces 90g : 210 kcal / G:35g / L:6g / P:4g
  Egg waffle HK 1 entier 150g : 380 kcal / G:55g / L:14g / P:8g
  Pandan cake 1 part 80g : 265 kcal / G:40g / L:10g / P:4g
  Kue lapis (gâteau couches) 60g : 180 kcal / G:32g / L:5g / P:2g
  Halo-halo philippin 1 bol 300g : 350-450 kcal / G:70-90g / L:5-12g
  Gulab jamun 2 pièces 80g : 280 kcal / G:45g / L:9g / P:4g
  Jalebi 60g : 230 kcal / G:45g / L:5g / P:2g
  Halva 50g : 250 kcal / G:28g / L:14g / P:5g
  Baklava 1 pièce 40g : 185 kcal / G:22g / L:10g / P:2g
  Loukoum 1 pièce 15g : 55 kcal / G:13g / L:0g
  Kunafa 1 part 100g : 350 kcal / G:42g / L:17g / P:7g
  Takoyaki sucré 1 pièce 30g : 55 kcal / G:8g / L:2g / P:2g
  Bubble tea sans perles 400ml : 180-250 kcal / G:40-55g / L:3-6g
  Bubble tea avec perles tapioca 500ml : 280-380 kcal / G:65-85g / L:3-8g
  Taro milk tea 400ml : 280 kcal / G:45g / L:8g / P:3g

DESSERTS LATINOS ET AUTRES :
  Churros 100g avec sauce chocolat : 420 kcal / G:50g / L:21g / P:6g
  Tres leches cake 1 part 120g : 380 kcal / G:50g / L:17g / P:8g
  Flan / crème caramel 120g : 200 kcal / G:30g / L:6g / P:6g
  Alfajor 1 pièce 50g : 210 kcal / G:30g / L:9g / P:2.5g
  Brigadeiro 1 pièce 20g : 90 kcal / G:13g / L:4g / P:1g
  Pastel de nata 1 pièce 80g : 265 kcal / G:33g / L:13g / P:5g
  Knafeh 1 part 100g : 350 kcal / G:42g / L:17g / P:7g

BOISSONS SUCRÉES ET SODAS :
  Coca-Cola 330ml (canette) : 139 kcal / G:35g
  Coca-Cola Zero / Diet 330ml : 1 kcal
  Pepsi 330ml : 150 kcal / G:37g
  Sprite / 7Up 330ml : 136 kcal / G:34g
  Orangina 330ml : 145 kcal / G:34g
  Fanta orange 330ml : 141 kcal / G:35g
  Schweppes tonic 330ml : 109 kcal / G:27g
  Red Bull 250ml : 113 kcal / G:28g
  Monster 500ml : 225 kcal / G:54g
  Lipton Ice Tea pêche 330ml : 122 kcal / G:29g
  Innocent smoothie fruits 250ml : 120-150 kcal / G:28-35g
  Jus d'orange 250ml : 110 kcal / G:25g
  Lait entier 250ml : 161 kcal / P:8g / G:12g / L:9g
  Lait écrémé 250ml : 88 kcal / P:8.5g / G:12g / L:0.1g
  Café noir espresso 30ml : 2 kcal
  Latte / cappuccino lait entier 250ml : 120-150 kcal / P:6g / G:12g / L:6g
  Matcha latte 300ml : 180 kcal / G:25g / L:6g / P:5g
  Calpico / Calpis 300ml : 135 kcal / G:32g
  Ramune 200ml : 84 kcal / G:21g
  Yakult 65ml : 50 kcal / G:11g
  Pocari Sweat 500ml : 130 kcal / G:31g
  100Plus / isotonique 500ml : 125 kcal / G:30g
  Lassi mangue 300ml : 210 kcal / G:38g / L:4g / P:5g
  Agua fresca 300ml : 90-120 kcal / G:22-30g

ALCOOLS ET BIÈRES :
  MÉTHODE PHOTO ÉTIQUETTE : si l'image montre une étiquette de vin/bière, identifier marque + millésime + type et calculer depuis la teneur en alcool visible (% ABV). Formule : kcal alcool = volume_ml × degré_alcool/100 × 0.789 × 7. Ajouter résidus sucrés selon style.
  
  Verre de vin rouge standard 150ml (12-14% ABV) : 125-145 kcal / G:3-4g / alcool:18g
  Verre de vin blanc sec 150ml (11-13% ABV) : 115-130 kcal / G:1-2g / alcool:16g
  Verre de vin blanc moelleux 150ml : 160-190 kcal / G:12-18g / alcool:15g
  Verre de champagne / prosecco 125ml : 95-105 kcal / G:3g / alcool:13g
  Verre de rosé 150ml (12% ABV) : 120-130 kcal / G:4g / alcool:16g
  Pinte de bière blonde 500ml (5% ABV) : 215 kcal / G:17g / alcool:20g
  Pinte de bière brune 500ml (6% ABV) : 260 kcal / G:20g / alcool:24g
  Bière légère / light 330ml (3.5% ABV) : 100 kcal / G:5g / alcool:9g
  Canette bière standard 330ml (5% ABV) : 142 kcal / G:11g / alcool:13g
  Craft IPA 330ml (6.5% ABV) : 195 kcal / G:16g / alcool:17g
  Soju 50ml (25% ABV) : 100 kcal / alcool:10g
  Shochu 50ml (25% ABV) : 97 kcal / alcool:9.8g
  Whisky / rhum / vodka 40ml (40% ABV) : 110 kcal / alcool:13g
  Gin tonic 200ml : 143 kcal / G:14g / alcool:14g
  Mojito 250ml : 190 kcal / G:24g / alcool:14g
  Margarita 150ml : 200 kcal / G:14g / alcool:20g
  Spritz Aperol 200ml : 160 kcal / G:18g / alcool:11g
  Sangria 200ml : 160 kcal / G:20g / alcool:14g
  Hard seltzer 330ml (4-5% ABV) : 95-110 kcal / G:1-3g
  Cidre brut 330ml (5% ABV) : 152 kcal / G:13g / alcool:13g

═══ ÉTAPE 4 — AJUSTEMENTS CONTEXTUELS ═══
Street food / marché : portions souvent plus petites mais riches en graisses de cuisson — appliquer +15g lipides cuisson
Restaurant : +35% lipides vs estimation maison (huiles cachées, beurre finish)
Fast-food : utiliser calories connues réelles (Big Mac 550 kcal, portion frites standard 365 kcal, Chicken McNuggets 10pc 470 kcal)
Takeaway barquette : portion généreuse — ajuster riz ou féculent à 280-350g minimum
Ramen / Pho / soupe repas : compter le bouillon (50-100 kcal/bol) + nouilles + protéine séparément
Repas partagé (style asiatique, plats au centre de la table) : détecter le contexte, estimer pour 1 portion individuelle (environ 1/4 à 1/3 du plat visible), indiquer "shared_dish: true" dans le JSON
Étiquette vin/bière visible : identifier la boisson depuis l'étiquette, calculer calories pour 1 verre standard (150ml vin, 330ml bière)
Photo avec boisson à côté du repas : inclure la boisson dans le breakdown et dans les macros totales

═══ ÉTAPE 5 — RÈGLES ANTI-SOUS-ESTIMATION ═══
- Si tu hésites entre deux grammages, prendre le plus élevé
- Riz dans un restaurant asiatique = 250-350g cuit (jamais 100g)
- Brochette de viande grasse (porc, agneau) tenue à la main = 100-150g + graisse de cuisson
- Visible ou pas, toujours compter la matière grasse de cuisson
- Plat avec sauce épaisse (curry, ragù, ragoût) = la sauce ajoute 100-200 kcal/portion
- Boisson alcoolisée visible = toujours l'inclure dans le total (les calories alcool sont souvent oubliées)
- Dessert avec chantilly ou sauce chocolat = compter la garniture séparément${extra}

═══ FORMAT DE RÉPONSE ═══
Réponds UNIQUEMENT en JSON valide sans markdown ni backticks :
{
  "dish_name": "Nom précis du plat (et origine si pertinente)",
  "context": "street_food | restaurant | fast_food | takeaway | home | cafe | market_stall",
  "cooking_method": "fried | grilled | steamed | raw | braised | stir_fried | mixed",
  "confidence": 0.85,
  "needs_clarification": false,
  "clarification_question": null,
  "ingredients_breakdown": [
    {"name": "Poulet grillé (cuisse)", "estimated_grams": 150, "calories": 315, "protein": 39, "carbs": 0, "fat": 16.5},
    {"name": "Riz jasmin cuit", "estimated_grams": 280, "calories": 364, "protein": 7.6, "carbs": 78, "fat": 0.8},
    {"name": "Sauce satay cacahuète", "estimated_grams": 40, "calories": 250, "protein": 10.6, "carbs": 9.3, "fat": 21},
    {"name": "Huile cuisson estimée", "estimated_grams": 12, "calories": 106, "protein": 0, "carbs": 0, "fat": 12}
  ],
  "macros": {"protein": 57, "carbs": 87, "fat": 50, "calories": 1035},
  "meal_type": "lunch",
  "accuracy_note": "Portion street food estimée — cuisse poulet grillée 150g, riz généreusement dosé, sauce cacahuète incluse"
}`;
}

// ─── SYSTEM PROMPTS — Coach & Chef conversationnels ─────────────────────────
const SYSTEM_PROMPTS = {
  coach: `Tu es le Coach IA de ForkAndForge, une app de musculation. Tu parles à un débutant en salle de sport.
Ton rôle : répondre à ses questions sur l'entraînement, la technique, la programmation, la récupération et la motivation.
STYLE : chaleureux, direct, encourageant. Phrases courtes. Pas de jargon sans l'expliquer. Tutoiement.
PRINCIPES : privilégie toujours la bonne forme à la charge lourde (anti ego-lifting). Rappelle la sécurité (dos neutre, contrôle, échauffement) quand c'est pertinent.
Si une question relève de la nutrition/recettes, suggère de basculer vers le Chef IA.
Si une question relève du médical (douleur, blessure), conseille de consulter un professionnel — tu n'es pas médecin.
Réponds en français, de façon concise (3-6 phrases sauf si on te demande un détail). Pas de markdown lourd, pas de listes à rallonge.`,
  chef: `Tu es le Chef IA de ForkAndForge. Tu es un chef cuisinier pro spécialisé en nutrition sportive, qui parle à un débutant.
Ton rôle : répondre à ses questions sur les repas, recettes, macros, idées de plats adaptés à son objectif (sèche, prise de masse, recomposition).
STYLE : passionné, pratique, accessible. Tutoiement. Astuces de chef concrètes (température, timing, texture).
PRINCIPES : recettes réalisables par un débutant, ingrédients simples. Adapte-toi silencieusement aux restrictions (halal, vegan, allergies) si mentionnées — sans les commenter.
Si une question relève de l'entraînement, suggère de basculer vers le Coach IA.
Réponds en français, de façon concise (3-6 phrases sauf demande de recette détaillée). Pas de markdown lourd.`
};

async function callClaude(route, clientBody) {
  const configMax = CLAUDE_CONFIG.max_tokens_by_route[route] || 1000;
  // Permettre au client de demander plus (dans la limite de la config)
  const clientMax = clientBody.max_tokens ? parseInt(clientBody.max_tokens) : 0;
  const maxTokens = clientMax > 0 ? Math.min(clientMax, configMax) : configMax;
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

  // System prompt pour le chat conversationnel (coach ou chef)
  let systemPrompt = null;
  if (route === 'coach') {
    const mode = clientBody.mode === 'chef' ? 'chef' : 'coach';
    systemPrompt = SYSTEM_PROMPTS[mode];
    // Injecter le contexte utilisateur (objectif, programme, ingrédients, menu)
    if (clientBody.context && typeof clientBody.context === 'object') {
      try {
        const ctxStr = JSON.stringify(clientBody.context, null, 0).slice(0, 2500);
        systemPrompt += `\n\nCONTEXTE DE L'UTILISATEUR (utilise-le pour personnaliser tes réponses, ne le récite pas tel quel) :\n${ctxStr}`;
        if (mode === 'chef') {
          systemPrompt += `\nIMPORTANT CHEF : si tu proposes des repas, respecte le programme d'entraînement (plus de glucides les jours de grosse séance) ET garde les ingrédients que l'utilisateur a déjà choisis (aliments_aimes). Évite aliments_evites et allergies absolument.`;
        }
        if (mode === 'coach') {
          systemPrompt += `\nIMPORTANT COACH : tiens compte du programme et de l'objectif de l'utilisateur. Si tu suggères de modifier le programme, explique pourquoi clairement.`;
        }
      } catch (e) { /* contexte ignoré si invalide */ }
    }
  }

  const apiBody = { model: CLAUDE_CONFIG.model, max_tokens: maxTokens, messages };
  if (systemPrompt) apiBody.system = systemPrompt;

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify(apiBody)
  });
  return response.json();
}

// ─── ROUTES HEALTH ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', version: '3.0', service: 'ForkAndForge Backend', db: 'postgresql' });
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

// Suppression de compte (droit RGPD) — ne dépend PAS d'un abonnement actif :
// un utilisateur dont l'essai/abo a expiré doit pouvoir supprimer son compte.
app.delete('/account', async (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Token manquant' });

  try {
    const sessionRes = await pool.query('SELECT email FROM sessions WHERE token = $1', [token]);
    if (!sessionRes.rows.length) return res.status(401).json({ error: 'Session invalide — reconnecte-toi' });

    const email = sessionRes.rows[0].email;
    // Supprime l'utilisateur ; les sessions liées partent en cascade (ON DELETE CASCADE).
    await pool.query('DELETE FROM users WHERE email = $1', [email]);
    // Filet de sécurité au cas où la cascade ne serait pas active.
    await pool.query('DELETE FROM sessions WHERE email = $1', [email]);

    console.log('Compte supprimé:', email);
    res.json({ ok: true, deleted: true });
  } catch (e) {
    console.error('account delete error:', e.message);
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
  if (!quota.allowed) {
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

// ─── Route admin — token développeur permanent ───────────────────────────────
// Usage : GET /admin/dev-token?secret=FITFORGE_DEV_2026
// Crée un compte dev avec abo actif permanent + quotas illimités
app.get('/admin/dev-token', async (req, res) => {
  const ADMIN_SECRET = 'FITFORGE_DEV_2026';
  if (req.query.secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Accès refusé' });
  const DEV_EMAIL = 'dev@fitforge.internal';
  const DEV_EXPIRES = new Date('2099-01-01').getTime();
  const EMPTY_QUOTAS = JSON.stringify({ photo_scans: 0, recipes: 0, programs: 0, coach_messages: 0 });
  try {
    const existing = await pool.query('SELECT email FROM users WHERE email = $1', [DEV_EMAIL]);
    if (existing.rows.length === 0) {
      await pool.query(
        'INSERT INTO users (email, password_hash, created_at, subscription_status, trial_ends_at, subscription_ends_at, plan, quotas_used, extra_quotas, quota_reset_date) VALUES ($1,$2,$3,$4,$5,$5,$6,$7,$8,$3)',
        [DEV_EMAIL, hashPassword('dev_internal'), Date.now(), 'active', DEV_EXPIRES, 'dev', EMPTY_QUOTAS, EMPTY_QUOTAS]
      );
    } else {
      await pool.query(
        'UPDATE users SET subscription_status=$1, subscription_ends_at=$2, plan=$3 WHERE email=$4',
        ['active', DEV_EXPIRES, 'dev', DEV_EMAIL]
      );
    }
    await pool.query('DELETE FROM sessions WHERE email = $1', [DEV_EMAIL]);
    const devToken = crypto.randomBytes(32).toString('hex');
    await pool.query('INSERT INTO sessions (token, email, expires_at) VALUES ($1,$2,$3)', [devToken, DEV_EMAIL, DEV_EXPIRES]);
    res.json({
      success: true,
      dev_token: devToken,
      email: DEV_EMAIL,
      expires: 'jamais (2099)',
      copy_paste: 'localStorage.setItem("ff_jwt","' + devToken + '");localStorage.setItem("ff_email","' + DEV_EMAIL + '")'
    });
    console.log('[ADMIN] Token dev généré');
  } catch(e) { res.status(500).json({ error: e.message }); }
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
      console.log(`FitForge Backend v2.9 (PostgreSQL) running on port ${PORT}`);
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
