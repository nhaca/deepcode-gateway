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

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { model, messages, stream } = req.body;

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
        // Streaming response - pipe directly
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
              const chunk = decoder.decode(value, { stream: true });
              res.write(chunk);
            }
          } catch (e) {
            // Stream interrupted
          }
          res.end();
          return;
        }

        // Non-streaming response
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
}
