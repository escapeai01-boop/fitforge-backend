const express = require('express');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json({ limit: '20mb' }));

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const PORT = process.env.PORT || 3000;

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'FitForge API running', version: '1.0' });
});

// Analyze food photo
app.post('/analyze-food', async (req, res) => {
  try {
    const { image_base64, media_type } = req.body;
    if (!image_base64 || !media_type) {
      return res.status(400).json({ error: 'Missing image_base64 or media_type' });
    }

    const PROMPT = 'You are a professional nutritionist and food analyst with visual expertise.\n\nSTEP 1 — VISUAL OBSERVATION (mandatory, list at least 4 clues):\nExamine: main protein source, carbohydrate source, vegetables, sauces/dressings, plate size, presentation style.\n\nSTEP 2 — IDENTIFICATION:\nBased ONLY on visual observations, identify the dish. DO NOT default to generic names without visual evidence.\n\nSTEP 3 — MACRO CALCULATION:\nUse standard nutritional databases. Realistic single-person portions.\n\nRespond ONLY in valid JSON (no markdown, no backticks):\n{"dish_name":"...","cuisine":"...","confidence":0.88,"visual_clues":["obs 1","obs 2","obs 3","obs 4"],"ingredients":[{"name":"...","qty_g":0,"visual_basis":"..."}],"macros":{"protein":0,"carbs":0,"fat":0,"calories":0},"portion_notes":"...","uncertainty":"...","goal_context":{"cut":"advice for cutting","bulk":"advice for bulking","lean":"advice for lean muscle","recomp":"advice for recomp"}}';

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type, data: image_base64 } },
            { type: 'text', text: PROMPT }
          ]
        }]
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({ error: data.error?.message || 'API error' });
    }

    const text = data.content?.[0]?.text || '';
    try {
      const clean = text.replace(/```json?|```/g, '').trim();
      const result = JSON.parse(clean);
      res.json(result);
    } catch (e) {
      const match = text.match(/\{[\s\S]*\}/);
      if (match) res.json(JSON.parse(match[0]));
      else res.status(500).json({ error: 'Failed to parse AI response', raw: text });
    }

  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Generate recipe
app.post('/generate-recipe', async (req, res) => {
  try {
    const { goal, preferences, lang } = req.body;

    const prompt = `You are a fitness nutrition expert. Generate a detailed recipe adapted to:
- Goal: ${goal || 'recomp'}
- Preferences/restrictions: ${preferences || 'none'}
- Language: ${lang || 'fr'}

Respond ONLY in valid JSON:
{"title":"...","description":"...","prep_time_min":0,"macros_per_serving":{"protein":0,"carbs":0,"fat":0,"calories":0},"servings":1,"ingredients":[{"name":"...","qty":"..."}],"steps":["step 1","step 2"],"tips":"...","goal_note":"..."}`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    const text = data.content?.[0]?.text || '';
    const clean = text.replace(/```json?|```/g, '').trim();
    const match = text.match(/\{[\s\S]*\}/);
    const result = JSON.parse(clean || (match ? match[0] : '{}'));
    res.json(result);

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`FitForge backend running on port ${PORT}`);
});
