const { generateApiKey, revokeApiKey, listApiKeys, verifyApiKey } = require('../lib/api-keys');
const { GATEWAY_SECRET, hmacSign } = require('../lib/security');
const crypto = require('crypto');

// Server-side tier assignment — NEVER trust client
const ALLOWED_AUTO_TIERS = ['free']; // Only free can be auto-assigned
const PAID_TIERS = ['pro', 'premium', 'business']; // Require payment verification

module.exports = async (req, res) => {
  // Fix #15: Restrict CORS
  const origin = req.headers.origin;
  const ALLOWED_ORIGINS = ['https://deepcode-ide.vercel.app', 'http://localhost:3000', 'http://localhost:8080'];
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Email, X-Binding-Signature, X-Device-Id, X-User-Provider, X-Login-IP, X-Binding-Timestamp');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { method } = req;
  const email = req.headers['x-email'] || req.body?.email;

  // POST /api-keys - Generate new API key
  if (method === 'POST') {
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!email.includes('@')) return res.status(400).json({ error: 'Invalid email' });

    // Verify binding signature — REQUIRED, not optional
    const bindingSig = req.headers['x-binding-signature'];
    const deviceId = req.headers['x-device-id'];
    const provider = req.headers['x-user-provider'] || 'unknown';
    const loginIp = req.headers['x-login-ip'];
    const bindingTimestamp = req.headers['x-binding-timestamp'];

    if (!bindingSig || !bindingTimestamp || !deviceId) {
      return res.status(403).json({ error: 'Binding signature required' });
    }

    // Verify timestamp freshness (5 minutes)
    const ts = parseInt(bindingTimestamp);
    if (isNaN(ts) || Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
      return res.status(403).json({ error: 'Binding timestamp expired' });
    }

    const message = `${deviceId}:${email}:${provider}:${loginIp}:${bindingTimestamp}`;
    const expected = hmacSign(GATEWAY_SECRET, message);
    try {
      const valid = crypto.timingSafeEqual(
        Buffer.from(bindingSig, 'hex'),
        Buffer.from(expected, 'hex')
      );
      if (!valid) return res.status(403).json({ error: 'Invalid binding signature' });
    } catch (e) {
      return res.status(403).json({ error: 'Invalid binding signature format' });
    }

    // Fix #13: Server assigns tier — NEVER from client body
    // All new keys start as free. Paid tiers require payment verification.
    const tier = 'free';
    const keyData = await generateApiKey(email, tier, provider);

    return res.json({
      success: true,
      apiKey: keyData.key,
      email: keyData.email,
      tier: keyData.tier, // Always 'free' for new keys
      createdAt: keyData.createdAt,
      message: 'New keys start as Free. Upgrade requires payment verification.',
    });
  }

  // GET /api-keys - List API keys for email
  if (method === 'GET') {
    if (!email) return res.status(400).json({ error: 'Email required' });
    const keys = await listApiKeys(email);
    return res.json({ keys });
  }

  // DELETE /api-keys - Revoke API key
  if (method === 'DELETE') {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) return res.status(400).json({ error: 'API key required' });
    const revoked = await revokeApiKey(apiKey);
    return res.json({ success: revoked });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
