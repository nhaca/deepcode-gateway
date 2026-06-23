const { generateApiKey, revokeApiKey, listApiKeys, verifyApiKey } = require('../lib/api-keys');
const { GATEWAY_SECRET, hmacSign } = require('../lib/security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key, X-Email');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { method } = req;
  const email = req.headers['x-email'] || req.body?.email;

  // POST /api-keys - Generate new API key
  if (method === 'POST') {
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    // Verify binding signature (to prevent fake email)
    const bindingSig = req.headers['x-binding-signature'];
    const deviceId = req.headers['x-device-id'];
    const provider = req.headers['x-user-provider'] || 'unknown';
    const loginIp = req.headers['x-login-ip'];
    const bindingTimestamp = req.headers['x-binding-timestamp'];

    if (bindingSig && bindingTimestamp) {
      const message = `${deviceId}:${email}:${provider}:${loginIp}:${bindingTimestamp}`;
      const expected = hmacSign(GATEWAY_SECRET, message);
      if (bindingSig !== expected) {
        return res.status(403).json({ error: 'Invalid binding signature' });
      }
    }

    const tier = req.body?.tier || 'free';
    const keyData = generateApiKey(email, tier);
    
    return res.json({
      success: true,
      apiKey: keyData.key,
      email: keyData.email,
      tier: keyData.tier,
      createdAt: keyData.createdAt,
    });
  }

  // GET /api-keys - List API keys for email
  if (method === 'GET') {
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }
    const keys = listApiKeys(email);
    return res.json({ keys });
  }

  // DELETE /api-keys - Revoke API key
  if (method === 'DELETE') {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
      return res.status(400).json({ error: 'API key required' });
    }
    const revoked = revokeApiKey(apiKey);
    return res.json({ success: revoked });
  }

  return res.status(405).json({ error: 'Method not allowed' });
};
