const { verifyApiKey, getCredits } = require('../lib/api-keys');

module.exports = async (req, res) => {
  // Fix #15: Restrict CORS
  const origin = req.headers.origin;
  const ALLOWED_ORIGINS = ['https://deepcode-ide.vercel.app', 'http://localhost:3000', 'http://localhost:8080'];
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });

  const keyData = await verifyApiKey(apiKey);
  if (!keyData) return res.status(401).json({ error: 'Invalid API key' });

  const credits = await getCredits(apiKey);

  return res.json({
    success: true,
    tier: keyData.tier || 'free',
    email: keyData.email,
    credits: {
      remaining: credits.remaining,
      limit: credits.limit,
      resetAt: credits.resetAt,
    },
    tokensUsed: keyData.tokensUsed || 0,
    requestsToday: keyData.requestsToday || 0,
  });
};
