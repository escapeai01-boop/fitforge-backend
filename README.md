# FitForge Backend

API proxy pour FitForge — cache la clé Anthropic côté serveur.

## Endpoints

- `GET /` — health check
- `POST /analyze-food` — analyse photo repas
- `POST /generate-recipe` — génère une recette IA

## Deploy sur Railway

1. Push ce dossier sur GitHub
2. Railway → New Project → Deploy from GitHub
3. Ajouter variable d'environnement : `ANTHROPIC_API_KEY=sk-ant-...`
4. Railway génère une URL automatiquement (ex: `fitforge-backend.up.railway.app`)
5. Copier cette URL dans FitForge

## Variables d'environnement requises

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Ta clé API Anthropic |
| `PORT` | Auto-assigné par Railway |
