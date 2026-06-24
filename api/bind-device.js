const { GATEWAY_SECRET, hmacSign, generateSessionToken, deriveUserSecret } = require('../lib/security');
const { verifyApiKey } = require('../lib/api-keys');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Key');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Verify API key
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });
  const keyData = await verifyApiKey(apiKey);
  if (!keyData) return res.status(401).json({ error: 'Invalid API key' });

  if (!GATEWAY_SECRET) return res.status(500).json({ error: 'Server misconfigured' });

  const { deviceId, email, provider, ip, bindingTimestamp } = req.body;
  if (!deviceId || !email) return res.status(400).json({ error: 'deviceId and email required' });

  // Generate binding signature (stateless - IDE stores locally)
  const timestamp = bindingTimestamp || Date.now().toString();
  const message = `${deviceId}:${email}:${provider || ''}:${ip || ''}:${timestamp}`;
  const bindingSignature = hmacSign(GATEWAY_SECRET, message);

  // Generate session token (for v2+ requests, valid 24 hours)
  const session = generateSessionToken(apiKey, deviceId, email);

  // Derive user secret (for IDE to sign requests)
  const userSecret = deriveUserSecret(apiKey);

  return res.json({
    success: true,
    bindingSignature,
    bindingTimestamp: timestamp,
    sessionToken: session.token,
    sessionExpiresAt: session.expiresAt,
    userSecret, // IDE stores this locally to sign requests
  });
};
