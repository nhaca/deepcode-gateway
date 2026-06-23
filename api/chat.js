const crypto = require('crypto');

const GATEWAY_KEY = process.env.GATEWAY_KEY || 'deepcode-gw-key-2024';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dc-gw-secret-2024-secure';
const MAX_AGE_MS = 15000;

const PROVIDERS = {
  groq: {
    url: 'https://api.groq.com/openai/v1',
    keys: (process.env.GROQ_KEYS || '').split(',').filter(Boolean),
  },
  nvidia: {
    url: 'https://integrate.api.nvidia.com/v1',
    keys: (process.env.NVIDIA_KEYS || '').split(',').filter(Boolean),
  },
  openrouter: {
    url: 'https://openrouter.ai/api/v1',
    keys: (process.env.OPENROUTER_KEYS || '').split(',').filter(Boolean),
  },
  google: {
    url: 'https://generativelanguage.googleapis.com/v1beta/models',
    keys: (process.env.GOOGLE_KEYS || '').split(',').filter(Boolean),
  },
};

const KEY_INDEX = { groq: 0, nvidia: 0, openrouter: 0, google: 0 };

function getNextKey(provider) {
  const keys = PROVIDERS[provider]?.keys || [];
  if (keys.length === 0) return null;
  const key = keys[KEY_INDEX[provider] % keys.length];
  KEY_INDEX[provider] = (KEY_INDEX[provider] + 1) % keys.length;
  return key;
}

const ALLOWED_DEVICES = new Set(['deepcode-ide-v1']);
const rateLimits = new Map();

function verifySignature(signature, timestamp, bodyStr, deviceId) {
  const age = Date.now() - parseInt(timestamp);
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) return false;
  if (!ALLOWED_DEVICES.has(deviceId)) return false;

  const message = `${timestamp}:${deviceId}:${bodyStr}`;
  const expected = crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');
  return signature === expected;
}

function checkRateLimit(deviceId, max = 50, windowMs = 60000) {
  const now = Date.now();
  const r = rateLimits.get(deviceId) || { count: 0, resetAt: now + windowMs };
  if (now > r.resetAt) { r.count = 0; r.resetAt = now + windowMs; }
  r.count++;
  rateLimits.set(deviceId, r);
  return r.count <= max;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Timestamp, X-Signature, X-Device-ID, X-Platform, X-Version');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Layer 1: API Key
  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) return res.status(401).json({ error: 'Unauthorized' });

  // Layer 2: Device
  const deviceId = req.headers['x-device-id'];
  const platform = req.headers['x-platform'];
  const version = req.headers['x-version'];
  if (!deviceId || !platform || !version) return res.status(401).json({ error: 'Missing device info' });
  if (!ALLOWED_DEVICES.has(deviceId)) return res.status(403).json({ error: 'Device not registered' });

  // Layer 3: Rate limit
  if (!checkRateLimit(deviceId)) return res.status(429).json({ error: 'Rate limit exceeded' });

  // Layer 4: Signature
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  if (!timestamp || !signature) return res.status(401).json({ error: 'Missing signature' });

  let bodyStr;
  try { bodyStr = JSON.stringify(req.body); } catch { return res.status(400).json({ error: 'Invalid body' }); }

  if (!verifySignature(signature, timestamp, bodyStr, deviceId)) {
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // Layer 5: Validation
  const { model, messages, stream } = req.body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Messages required' });
  }
  if (bodyStr.length > 100000) return res.status(413).json({ error: 'Request too large' });

  // Route to provider
  const providerList = Object.keys(PROVIDERS).filter(p => PROVIDERS[p].keys.length > 0);
  let lastError;

  for (const provider of providerList) {
    const key = getNextKey(provider);
    if (!key) continue;

    const baseUrl = PROVIDERS[provider].url;
    const apiModel = provider === 'google' ? 'gemini-2.5-flash' : model || 'auto';

    try {
      const url = provider === 'google'
        ? `${baseUrl}/${apiModel}:generateContent?key=${key}`
        : `${baseUrl}/chat/completions`;

      const headers = { 'Content-Type': 'application/json' };
      if (provider !== 'google') headers['Authorization'] = `Bearer ${key}`;

      const providerBody = provider === 'google'
        ? { contents: [{ parts: [{ text: messages.map(m => m.content).join('\n') }] }] }
        : { model: apiModel, messages, stream: !!stream };

      const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(providerBody) });

      if (response.ok) {
        if (stream && provider !== 'google') {
          res.setHeader('Content-Type', 'text/event-stream');
          res.setHeader('Cache-Control', 'no-cache');
          res.setHeader('Connection', 'keep-alive');
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              res.write(decoder.decode(value, { stream: true }));
            }
          } catch {}
          return res.end();
        }

        const data = await response.json();
        if (provider === 'google') {
          const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
          return res.json({ choices: [{ message: { content } }] });
        }
        return res.json(data);
      }

      lastError = `${provider}: ${response.status}`;
    } catch (e) {
      lastError = `${provider}: ${e.message}`;
    }
  }

  return res.status(500).json({ error: lastError || 'All providers failed' });
};

