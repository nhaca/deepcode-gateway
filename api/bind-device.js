const { GATEWAY_SECRET, hmacSign } = require('../lib/security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Client-ID');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Verify client ID
  const clientId = req.headers['x-client-id'];
  if (!clientId || !clientId.startsWith('dc-')) {
    return res.status(401).json({ error: 'Missing or invalid client ID' });
  }

  if (!GATEWAY_SECRET) {
    return res.status(500).json({ error: 'Server misconfigured' });
  }

  const { deviceId, email, provider, ip, bindingTimestamp } = req.body;
  if (!deviceId || !email) {
    return res.status(400).json({ error: 'deviceId and email required' });
  }

  // Generate binding signature (stateless - IDE stores locally)
  const timestamp = bindingTimestamp || Date.now().toString();
  const message = `${deviceId}:${email}:${provider || ''}:${ip || ''}:${timestamp}`;
  const bindingSignature = hmacSign(GATEWAY_SECRET, message);

  return res.json({
    success: true,
    bindingSignature,
    bindingTimestamp: timestamp,
  });
};
