const { GATEWAY_KEY, GATEWAY_SECRET, hmacSign, verifyBindingSignature } = require('../lib/security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Binding-Signature, X-Binding-Timestamp');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Verify gateway key
  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return res.status(401).json({ error: 'Unauthorized' });
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
