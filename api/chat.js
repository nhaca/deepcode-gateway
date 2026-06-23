const { verifySignature, getDeviceFingerprint, verifyDevice, checkRateLimit, MAX_AGE_MS } = require('../lib/security');

const GATEWAY_KEY = process.env.GATEWAY_KEY || 'deepcode-gw-key-2024';

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

export const config = { runtime: 'edge' };

export default async function handler(req) {
  // CORS
  if (req.method === 'OPTIONS') {
    return new Response(null, { 
      headers: { 
        'Access-Control-Allow-Origin': '*', 
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Signature, X-Device-ID, X-Platform, X-Version' 
      } 
    });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 });
  }

  // ========== LAYER 1: API Key ==========
  const auth = req.headers.get('authorization');
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  // ========== LAYER 2: Device Check ==========
  const deviceId = req.headers.get('x-device-id');
  const platform = req.headers.get('x-platform');
  const version = req.headers.get('x-version');
  
  if (!deviceId || !platform || !version) {
    return new Response(JSON.stringify({ error: 'Missing device info' }), { status: 401 });
  }

  if (!verifyDevice(deviceId)) {
    return new Response(JSON.stringify({ error: 'Device not registered' }), { status: 403 });
  }

  // ========== LAYER 3: Rate Limit ==========
  if (!checkRateLimit(deviceId, 50, 60000)) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), { status: 429 });
  }

  // ========== LAYER 4: Signature ==========
  const timestamp = req.headers.get('x-timestamp');
  const signature = req.headers.get('x-signature');
  const bodyStr = await req.text();

  if (!timestamp || !signature) {
    return new Response(JSON.stringify({ error: 'Missing signature' }), { status: 401 });
  }

  const valid = await verifySignature(signature, timestamp, bodyStr, deviceId);
  if (!valid) {
    return new Response(JSON.stringify({ error: 'Invalid signature or expired' }), { status: 401 });
  }

  // ========== LAYER 5: Request Validation ==========
  let body;
  try {
    body = JSON.parse(bodyStr);
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid JSON' }), { status: 400 });
  }

  const { model, messages, stream } = body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return new Response(JSON.stringify({ error: 'Messages required' }), { status: 400 });
  }

  // Limit message size
  if (bodyStr.length > 100000) {
    return new Response(JSON.stringify({ error: 'Request too large' }), { status: 413 });
  }

  // ========== ROUTE TO PROVIDER ==========
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
      if (provider !== 'google') {
        headers['Authorization'] = `Bearer ${key}`;
      }

      const providerBody = provider === 'google'
        ? { contents: [{ parts: [{ text: messages.map(m => m.content).join('\n') }] }] }
        : { model: apiModel, messages, stream: !!stream };

      const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(providerBody) });

      if (response.ok) {
        // Streaming
        if (stream && provider !== 'google') {
          const headers = new Headers();
          headers.set('Content-Type', 'text/event-stream');
          headers.set('Cache-Control', 'no-cache');
          headers.set('Connection', 'keep-alive');
          headers.set('Access-Control-Allow-Origin', '*');
          return new Response(response.body, { headers });
        }

        // Non-streaming
        const data = await response.json();

        if (provider === 'google') {
          const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
          return Response.json({ choices: [{ message: { content } }] });
        }

        return Response.json(data);
      }

      lastError = `${provider}: ${response.status}`;
    } catch (e) {
      lastError = `${provider}: ${e.message}`;
    }
  }

  return Response.json({ error: lastError || 'All providers failed' }, { status: 500 });
}
