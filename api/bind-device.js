const { bindDevice, verifyDeviceBinding, getDeviceBinding, GATEWAY_KEY } = require('../lib/security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Verify gateway key
  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { action, deviceId, email, provider, ip } = req.body;
  if (!deviceId || !email) {
    return res.status(400).json({ error: 'deviceId and email required' });
  }

  if (action === 'bind') {
    const result = bindDevice(deviceId, email, provider || 'unknown', ip || 'unknown');
    return res.json(result);
  }

  if (action === 'verify') {
    const result = verifyDeviceBinding(deviceId, email);
    return res.json(result);
  }

  if (action === 'get') {
    const binding = getDeviceBinding(deviceId);
    return res.json({ binding });
  }

  return res.status(400).json({ error: 'Invalid action' });
};
