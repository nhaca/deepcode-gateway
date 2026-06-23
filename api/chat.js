const GATEWAY_KEY = process.env.GATEWAY_KEY || 'deepcode-gw-key-2024';

const PROVIDERS = {
  google: {
    url: 'https://generativelanguage.googleapis.com/v1beta/models',
    keys: (process.env.GOOGLE_KEYS || '').split(',').filter(Boolean),
  },
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
};

const KEY_INDEX = { google: 0, groq: 0, nvidia: 0, openrouter: 0 };

function getNextKey(provider) {
  const keys = PROVIDERS[provider]?.keys || [];
  if (keys.length === 0) return null;
  const key = keys[KEY_INDEX[provider] % keys.length];
  KEY_INDEX[provider] = (KEY_INDEX[provider] + 1) % keys.length;
  return key;
}

export const config = { runtime: 'edge' };

export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization' } });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 });
  }

  const auth = req.headers.get('authorization');
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  }

  const { model, messages, stream } = await req.json();

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
        // Streaming response
        if (stream && provider !== 'google') {
          return new Response(response.body, {
            headers: {
              'Content-Type': 'text/event-stream',
              'Cache-Control': 'no-cache',
              'Connection': 'keep-alive',
              'Access-Control-Allow-Origin': '*',
            },
          });
        }

        // Non-streaming response
        const data = await response.json();

        if (provider === 'google') {
          const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
          return new Response(JSON.stringify({ choices: [{ message: { content } }] }), {
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
          });
        }

        return new Response(JSON.stringify(data), {
          headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
        });
      }

      lastError = `${provider}: ${response.status}`;
    } catch (e) {
      lastError = `${provider}: ${e.message}`;
    }
  }

  return new Response(JSON.stringify({ error: lastError || 'All providers failed' }), {
    status: 500,
    headers: { 'Content-Type': 'application/json' },
  });
}
