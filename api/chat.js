const {
  securityCheck,
  bindDevice,
  verifyDeviceBinding,
  getClientIp,
  GATEWAY_KEY,
} = require('../lib/security');

// ===== Provider Config =====
const PROVIDERS = {
  groq: {
    url: 'https://api.groq.com/openai/v1',
    keys: (process.env.GROQ_KEYS || '').split(',').filter(Boolean),
    priority: 1,
  },
  nvidia: {
    url: 'https://integrate.api.nvidia.com/v1',
    keys: (process.env.NVIDIA_KEYS || '').split(',').filter(Boolean),
    priority: 2,
  },
  openrouter: {
    url: 'https://openrouter.ai/api/v1',
    keys: (process.env.OPENROUTER_KEYS || '').split(',').filter(Boolean),
    priority: 3,
  },
  puter: {
    url: 'https://api.puter.com/puterai/openai/v1',
    keys: (process.env.PUTER_KEYS || '').split(',').filter(Boolean),
    priority: 4,
    isPuter: true,
  },
  google: {
    url: 'https://generativelanguage.googleapis.com/v1beta/models',
    keys: (process.env.GOOGLE_KEYS || '').split(',').filter(Boolean),
    priority: 5,
  },
};

const KEY_INDEX = { groq: 0, nvidia: 0, openrouter: 0, puter: 0, google: 0 };

function getNextKey(provider) {
  const keys = PROVIDERS[provider]?.keys || [];
  if (keys.length === 0) return null;
  const key = keys[KEY_INDEX[provider] % keys.length];
  KEY_INDEX[provider] = (KEY_INDEX[provider] + 1) % keys.length;
  return key;
}

// ===== Version → Model Mapping =====
const VERSION_MODELS = {
  1: { defaultModel: 'auto', label: 'DeepCode Go' },
  2: { defaultModel: 'z-ai/glm-4.7-flash-free', label: 'DeepCode Pro' },
  3: { defaultModel: 'z-ai/glm-5.1', label: 'DeepCode Ultra' },
  4: { defaultModel: 'auto', label: 'DeepCode Server 2' },
};

// v4 model-specific routing: /v4/chat/completions/claude-opus-4-8
const V4_MODELS = {
  'claude-opus-4-8': { provider: 'openrouter', model: 'anthropic/claude-opus-4', name: 'Claude Opus 4.8' },
  'claude-sonnet-4': { provider: 'openrouter', model: 'anthropic/claude-sonnet-4', name: 'Claude Sonnet 4' },
  'gpt-5': { provider: 'openrouter', model: 'openai/gpt-5', name: 'GPT-5' },
  'gpt-4.1': { provider: 'openrouter', model: 'openai/gpt-4.1', name: 'GPT-4.1' },
  'deepseek-v4': { provider: 'nvidia', model: 'deepseek-ai/deepseek-v4-flash', name: 'DeepSeek V4' },
  'glm-5.1': { provider: 'nvidia', model: 'z-ai/glm-5.1', name: 'GLM 5.1' },
  'gemini-2.5-flash': { provider: 'google', model: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash' },
  'llama-4-maverick': { provider: 'openrouter', model: 'meta-llama/llama-4-maverick', name: 'Llama 4 Maverick' },
  'qwen-3-235b': { provider: 'openrouter', model: 'qwen/qwen3-235b-a22b', name: 'Qwen 3 235B' },
};

// v4 tier restrictions
const V4_TIER_RESTRICTED = {
  'claude-opus-4-8': ['pro', 'premium', 'business'],
  'claude-sonnet-4': ['pro', 'premium', 'business'],
  'gpt-5': ['premium', 'business'],
  'gpt-4.1': ['pro', 'premium', 'business'],
  'deepseek-v4': ['pro', 'premium', 'business'],
  'glm-5.1': ['pro', 'premium', 'business'],
  'gemini-2.5-flash': ['pro', 'premium', 'business'],
  'llama-4-maverick': ['pro', 'premium', 'business'],
  'qwen-3-235b': ['pro', 'premium', 'business'],
};

// ===== CORS Handler =====
function handleCors(res, req) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Timestamp, X-Signature, X-Device-ID, X-Platform, X-Version, X-User-Email, X-User-Provider, X-User-Tier, X-GitHub-Token, X-Binding-Signature, X-Binding-Timestamp, X-Login-IP'
  );
  if (req.method === 'OPTIONS') { res.status(200).end(); return true; }
  return false;
}

// ===== Provider Call =====
async function callProvider(providerName, model, messages, stream, extraHeaders = {}) {
  const provider = PROVIDERS[providerName];
  if (!provider) throw new Error(`Unknown provider: ${providerName}`);

  const key = getNextKey(providerName);
  if (!key) throw new Error(`No keys for provider: ${providerName}`);

  const headers = { 'Content-Type': 'application/json' };
  if (providerName !== 'google') headers['Authorization'] = `Bearer ${key}`;
  Object.assign(headers, extraHeaders);

  const isGoogle = providerName === 'google';
  const apiModel = isGoogle ? 'gemini-2.5-flash' : model;
  const url = isGoogle
    ? `${provider.url}/${apiModel}:generateContent?key=${key}`
    : `${provider.url}/chat/completions`;

  const body = isGoogle
    ? { contents: [{ parts: [{ text: messages.map(m => m.content).join('\n') }] }] }
    : { model: apiModel, messages, stream: !!stream };

  const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`${providerName}: ${response.status} - ${err.error?.message || JSON.stringify(err)}`);
  }

  // Streaming (non-Google only)
  if (stream && !isGoogle) return response;

  const data = await response.json();
  if (isGoogle) {
    const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return { choices: [{ message: { content } }] };
  }
  return data;
}

// ===== Auto Route (try providers in order) =====
async function autoRoute(model, messages, stream) {
  const providerList = Object.keys(PROVIDERS)
    .filter(p => PROVIDERS[p].keys.length > 0)
    .sort((a, b) => PROVIDERS[a].priority - PROVIDERS[b].priority);

  let lastError;
  for (const provider of providerList) {
    try {
      const result = await callProvider(provider, model, messages, stream);
      return result;
    } catch (e) {
      lastError = e.message;
    }
  }
  throw new Error(lastError || 'All providers failed');
}

// ===== Device Binding IPC =====
async function handleBindDevice(req, res) {
  const { deviceId, email, provider, ip } = req.body;
  if (!deviceId || !email) {
    return res.status(400).json({ error: 'deviceId and email required' });
  }
  const result = bindDevice(deviceId, email, provider || 'unknown', ip || 'unknown');
  return res.json(result);
}

// ===== Main Chat Handler =====
async function handleChat(req, res, version, specificModel) {
  // Security check (includes API key, device, user identity, IP consistency, tier access)
  const sec = securityCheck(req, version);
  if (!sec.ok) {
    return res.status(sec.status).json({ error: sec.error });
  }

  const { model, messages, stream } = req.body;
  const userEmail = sec.userEmail;

  // v4: model-specific routing
  if (version === 4 && specificModel) {
    const modelConfig = V4_MODELS[specificModel];
    if (!modelConfig) {
      return res.status(400).json({ error: `Unknown model: ${specificModel}. Available: ${Object.keys(V4_MODELS).join(', ')}` });
    }

    // Check tier restriction
    const allowedTiers = V4_TIER_RESTRICTED[specificModel];
    if (allowedTiers && !allowedTiers.includes(sec.userTier)) {
      return res.status(403).json({
        error: `Model ${specificModel} requires: ${allowedTiers.join(', ')} tier`,
        required: allowedTiers,
        current: sec.userTier,
      });
    }

    // GitHub token pass-through
    const githubToken = req.headers['x-github-token'];
    const extraHeaders = {};
    if (githubToken) extraHeaders['X-GitHub-Token'] = githubToken;

    try {
      const result = await callProvider(modelConfig.provider, modelConfig.model, messages, stream, extraHeaders);
      if (stream && result?.body) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        const reader = result.body.getReader();
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
      return res.json(result);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // v4: auto-select or use model from body
  if (version === 4) {
    const reqModel = model || 'auto';
    // Check if requested model is in V4_MODELS
    if (V4_MODELS[reqModel]) {
      return handleChat(req, res, 4, reqModel);
    }
    // Auto route
    try {
      const result = await autoRoute(reqModel, messages, stream);
      if (stream && result?.body) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        const reader = result.body.getReader();
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
      return res.json(result);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // v1/v2/v3: standard routing
  const versionConfig = VERSION_MODELS[version];
  const apiModel = model || versionConfig.defaultModel;

  // v2: DeepCode Pro specific models
  if (version === 2) {
    const proModel = model || 'z-ai/glm-4.7-flash-free';
    try {
      const result = await autoRoute(proModel, messages, stream);
      if (stream && result?.body) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        const reader = result.body.getReader();
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
      return res.json(result);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // v3: DeepCode Ultra
  if (version === 3) {
    const ultraModel = model || 'z-ai/glm-5.1';
    try {
      const result = await autoRoute(ultraModel, messages, stream);
      if (stream && result?.body) {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        const reader = result.body.getReader();
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
      return res.json(result);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // v1: DeepCode Go (default, auto model)
  try {
    const result = await autoRoute(apiModel, messages, stream);
    if (stream && result?.body) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      const reader = result.body.getReader();
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
    return res.json(result);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}

// ===== Export =====
module.exports = async function handler(req, res) {
  if (handleCors(res, req)) return;
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Parse URL to determine version and optional model
  const url = new URL(req.url, 'http://localhost');
  const pathParts = url.pathname.split('/').filter(Boolean);
  // pathParts: ['v1', 'chat', 'completions'] or ['v4', 'chat', 'completions', 'claude-opus-4-8']

  let version = 1;
  let specificModel = null;

  if (pathParts[0] && pathParts[0].startsWith('v')) {
    version = parseInt(pathParts[0].substring(1)) || 1;
  }
  if (pathParts.length > 3 && pathParts[0].startsWith('v')) {
    specificModel = pathParts[3]; // e.g., 'claude-opus-4-8'
  }

  return handleChat(req, res, version, specificModel);
};

module.exports.handleBindDevice = handleBindDevice;
