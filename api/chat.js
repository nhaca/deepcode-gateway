const GATEWAY_KEY = process.env.GATEWAY_KEY || 'deepcode-gw-key-2024';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dc-gw-secret-2024-secure';
const MAX_AGE_MS = 30000;

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

async function hmacSign(secret, message) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifySignature(signature, timestamp, bodyStr) {
  const age = Date.now() - parseInt(timestamp);
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) return false;

  const message = `${timestamp}:${bodyStr}`;
  const expected = await hmacSign(GATEWAY_SECRET, message);
  return signature === expected;
}

export const config = { runtime: 'edge' };

export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Timestamp, X-Signature' } });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 });
  }

  // Verify API key
  const auth = req.headers.get('authorization');
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  // Verify signature
  const timestamp = req.headers.get('x-timestamp');
  const signature = req.headers.get('x-signature');
  const bodyStr = await req.text();

  if (!timestamp || !signature) {
    return new Response(JSON.stringify({ error: 'Missing signature' }), { status: 401 });
  }

  const valid = await verifySignature(signature, timestamp, bodyStr);
  if (!valid) {
    return new Response(JSON.stringify({ error: 'Invalid signature' }), { status: 401 });
  }

  const { model, messages, stream } = JSON.parse(bodyStr);

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

      const body = provider === 'google'
        ? { contents: [{ parts: [{ text: messages.map(m => m.content).join('\n') }] }] }
        : { model: apiModel, messages, stream: !!stream };

      const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });

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
