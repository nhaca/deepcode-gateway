const { securityCheck, getClientIp, getAuditLog, getSecurityStats } = require('../lib/security');

// ===== Provider Config =====
const PROVIDERS = {
  groq: {
    url: 'https://api.groq.com/openai/v1',
    keys: (process.env.GROQ_KEYS || '').split(',').filter(Boolean),
    priority: 1,
  },
  cerebras: {
    url: 'https://api.cerebras.ai/v1',
    keys: (process.env.CEREBRAS_KEYS || '').split(',').filter(Boolean),
    priority: 2,
  },
  sambanova: {
    url: 'https://api.sambanova.ai/v1',
    keys: (process.env.SAMBANOVA_KEYS || '').split(',').filter(Boolean),
    priority: 3,
  },
  nvidia: {
    url: 'https://integrate.api.nvidia.com/v1',
    keys: (process.env.NVIDIA_KEYS || '').split(',').filter(Boolean),
    priority: 4,
  },
  mistral: {
    url: 'https://api.mistral.ai/v1',
    keys: (process.env.MISTRAL_KEYS || '').split(',').filter(Boolean),
    priority: 5,
  },
  cohere: {
    url: 'https://api.cohere.com/v2',
    keys: (process.env.COHERE_KEYS || '').split(',').filter(Boolean),
    priority: 6,
    isOpenAICompat: false,
  },
  venice: {
    url: 'https://api.venice.ai/api/v1',
    keys: (process.env.VENICE_KEYS || '').split(',').filter(Boolean),
    priority: 7,
  },
  openrouter: {
    url: 'https://openrouter.ai/api/v1',
    keys: (process.env.OPENROUTER_KEYS || '').split(',').filter(Boolean),
    priority: 8,
  },
  llm7: {
    url: 'https://api.llm7.io/v1',
    keys: (process.env.LLM7_KEYS || '').split(',').filter(Boolean),
    priority: 9,
    noKeyRequired: true,
  },
  huggingface: {
    url: 'https://api-inference.huggingface.co/v1',
    keys: (process.env.HUGGINGFACE_KEYS || '').split(',').filter(Boolean),
    priority: 10,
  },
  kira: {
    url: 'https://kiraai.vn/api/v1',
    keys: (process.env.KIRA_KEYS || '').split(',').filter(Boolean),
    priority: 11,
  },
  ovhcloud: {
    url: 'https://api.ovhcloud.com/v1',
    keys: (process.env.OVHCLOUD_KEYS || '').split(',').filter(Boolean),
    priority: 12,
    noKeyRequired: true,
  },
  google: {
    url: 'https://generativelanguage.googleapis.com/v1beta',
    keys: (process.env.GOOGLE_KEYS || '').split(',').filter(Boolean),
    priority: 13,
  },
  github: {
    url: 'https://models.inference.ai.azure.com/v1',
    keys: [], // Uses user's own GitHub token via X-GitHub-Token header
    priority: 14,
    useUserToken: true,
  },
};

const KEY_INDEX = {};
for (const k of Object.keys(PROVIDERS)) KEY_INDEX[k] = 0;

function getNextKey(provider) {
  const keys = PROVIDERS[provider]?.keys || [];
  if (keys.length === 0) return null;
  const key = keys[KEY_INDEX[provider] % keys.length];
  KEY_INDEX[provider] = (KEY_INDEX[provider] + 1) % keys.length;
  return key;
}

// ===== Version → Model Mapping =====
const VERSION_MODELS = {
  1: { defaultModel: 'auto', label: 'DeepCode AI' },
  2: { defaultModel: 'z-ai/glm-5.1', label: 'DeepCode Pro' },
  3: { defaultModel: 'z-ai/glm-5.2-free', label: 'DeepCode Ultra' },
  4: { defaultModel: 'auto', label: 'DeepCode Server 2' },
};

// v4 model-specific routing
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
  'kira-3.5-flash': { provider: 'kira', model: 'kira-3.5-flash', name: 'Kira 3.5 Flash' },
  'kira-2.5-pro': { provider: 'kira', model: 'kira-2.5-pro', name: 'Kira 2.5 Pro' },
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
  'kira-3.5-flash': ['pro', 'premium', 'business'],
  'kira-2.5-pro': ['pro', 'premium', 'business'],
};

// ===== Allowed CORS origins =====
const ALLOWED_ORIGINS = [
  'electron://localhost',
  'capacitor://localhost',
  'http://localhost',
  'https://deepcode.vercel.app',
];

// ===== CORS Handler =====
function handleCors(res, req) {
  const origin = req.headers['origin'] || '';
  const allowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o)) || origin === '';
  res.setHeader('Access-Control-Allow-Origin', allowed ? (origin || '*') : ALLOWED_ORIGINS[0]);
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Timestamp, X-Signature, X-Device-ID, X-Platform, X-Version, X-User-Email, X-User-Provider, X-User-Tier, X-GitHub-Token, X-Binding-Signature, X-Binding-Timestamp, X-Login-IP, X-Api-Key, X-Admin-Secret, X-Session-Token'
  );
  if (req.method === 'OPTIONS') { res.status(200).end(); return true; }
  return false;
}

// ===== Streaming response handler (shared) =====
async function handleStreamResponse(res, response) {
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

// ===== Estimate tokens (simple: ~4 chars per token) =====
function estimateTokens(text) {
  return Math.ceil((text || '').length / 4);
}

function estimateMessagesTokens(messages) {
  return messages.reduce((sum, m) => sum + estimateTokens(m.content) + 4, 0);
}

// ===== Provider Call =====
// Kira rate limit: use global state instead of local variable (works in serverless)
if (!global.__kiraState) global.__kiraState = { lastCallTime: 0 };
const KIRA_MIN_DELAY_MS = 1000;

async function callProvider(providerName, model, messages, stream, extraHeaders = {}) {
  const provider = PROVIDERS[providerName];
  if (!provider) throw new Error(`Unknown provider: ${providerName}`);

  // Kira rate limit
  if (providerName === 'kira') {
    const now = Date.now();
    const elapsed = now - global.__kiraState.lastCallTime;
    if (elapsed < KIRA_MIN_DELAY_MS) await new Promise(r => setTimeout(r, KIRA_MIN_DELAY_MS - elapsed));
    global.__kiraState.lastCallTime = Date.now();
  }

  // GitHub Models: use user's own token
  if (provider.useUserToken) {
    const userToken = extraHeaders['X-GitHub-Token'];
    if (!userToken) throw new Error('GitHub token required for GitHub Models. Please connect GitHub in IDE.');
    const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${userToken}` };
    const apiModel = model || 'gpt-4o';
    const url = `${provider.url}/chat/completions`;
    const body = { model: apiModel, messages, stream: !!stream };
    const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(`GitHub Models: ${response.status} - ${err.error?.message || JSON.stringify(err)}`);
    }
    if (stream) return response;
    return await response.json();
  }

  const key = getNextKey(providerName);
  if (!key && !provider.noKeyRequired) throw new Error(`No keys for provider: ${providerName}`);

  const headers = { 'Content-Type': 'application/json' };
  if (key && providerName !== 'google') headers['Authorization'] = `Bearer ${key}`;
  Object.assign(headers, extraHeaders);

  const isGoogle = providerName === 'google';
  const isCohere = providerName === 'cohere';
  const apiModel = model || (isGoogle ? 'gemini-2.5-flash' : 'auto');

  let url, body;
  if (isGoogle) {
    url = `${provider.url}/models/${apiModel}:generateContent?key=${key}`;
    body = { contents: [{ parts: [{ text: messages.map(m => m.content).join('\n') }] }] };
  } else if (isCohere) {
    url = `${provider.url}/chat`;
    body = { model: apiModel || 'command-r', messages, stream: !!stream };
  } else {
    url = `${provider.url}/chat/completions`;
    body = { model: apiModel, messages, stream: !!stream };
  }

  const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(`${providerName}: ${response.status} - ${err.error?.message || JSON.stringify(err)}`);
  }

  if (stream && !isGoogle) return response;

  const data = await response.json();
  if (isGoogle) {
    const content = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    return { choices: [{ message: { content } }] };
  }
  if (isCohere) {
    const content = data.message?.content?.[0]?.text || data.text || '';
    return { choices: [{ message: { content } }] };
  }
  return data;
}

// ===== Auto Route with retry =====
async function callProviderWithRetry(providerName, model, messages, stream, extraHeaders = {}, maxRetries = 2) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await callProvider(providerName, model, messages, stream, extraHeaders);
    } catch (e) {
      const isRetryable = e.message.includes('429') || e.message.includes('500') || e.message.includes('502') || e.message.includes('503');
      if (isRetryable && attempt < maxRetries) {
        const delay = Math.pow(2, attempt + 1) * 1000;
        await new Promise(r => setTimeout(r, delay));
        continue;
      }
      throw e;
    }
  }
}

async function autoRoute(model, messages, stream, extraHeaders = {}) {
  // GitHub Models: route directly to GitHub provider
  if (model && model.startsWith('github:')) {
    const githubModel = model.replace('github:', '');
    return await callProviderWithRetry('github', githubModel, messages, stream, extraHeaders);
  }

  // Map 'auto' to default model per provider
  const AUTO_MODEL_MAP = {
    groq: 'llama-3.3-70b-versatile',
    cerebras: 'llama-3.3-70b',
    sambanova: 'DeepSeek-V3-0324',
    nvidia: 'meta/llama-3.3-70b-instruct',
    openrouter: 'meta-llama/llama-3.3-70b-instruct',
    mistral: 'mistral-small-latest',
    cohere: 'command-r',
    venice: 'venice-uncensored',
    llm7: 'meta-llama/llama-3.3-70b-instruct',
    huggingface: 'Qwen/Qwen3-8B',
    kira: 'kira-3.5-flash',
    ovhcloud: 'meta-llama/Meta-Llama-3.3-70B-Instruct',
    google: 'gemini-2.5-flash',
  };

  const providerList = Object.keys(PROVIDERS)
    .filter(p => PROVIDERS[p].keys.length > 0 || PROVIDERS[p].noKeyRequired)
    .sort((a, b) => PROVIDERS[a].priority - PROVIDERS[b].priority);

  let lastError;
  for (const provider of providerList) {
    try {
      const providerModel = (model === 'auto') ? (AUTO_MODEL_MAP[provider] || 'auto') : model;
      return await callProviderWithRetry(provider, providerModel, messages, stream);
    } catch (e) {
      lastError = e.message;
    }
  }
  throw new Error(lastError || 'All providers failed');
}

// ===== Stream or JSON response =====
async function respondWithResult(res, result, stream, req, version, sec) {
  if (stream && result?.body) {
    return handleStreamResponse(res, result);
  }
  // Track token usage (credits already deducted in handleChat)
  if (!stream && result?.choices?.[0]?.message?.content) {
    const tokens = estimateMessagesTokens(req.body.messages) + estimateTokens(result.choices[0].message.content);
    const { trackTokenUsage } = require('../lib/api-keys');
    trackTokenUsage(req.headers['x-api-key'], tokens).catch(() => {});
  }
  return res.json(result);
}

// ===== Main Chat Handler =====
async function handleChat(req, res, version, specificModel) {
  const sec = await securityCheck(req, version);
  if (!sec.ok) return res.status(sec.status).json({ error: sec.error });

  // Deduct credits upfront (works for both streaming and non-streaming)
  const apiKey = req.headers['x-api-key'];
  if (apiKey && sec.creditCost) {
    const { useCredits } = require('../lib/api-keys');
    useCredits(apiKey, sec.creditCost).catch(() => {});
  }

  const { model, messages, stream } = req.body;

  // v4: model-specific routing
  if (version === 4 && specificModel) {
    const modelConfig = V4_MODELS[specificModel];
    if (!modelConfig) return res.status(400).json({ error: `Unknown model: ${specificModel}. Available: ${Object.keys(V4_MODELS).join(', ')}` });

    const allowedTiers = V4_TIER_RESTRICTED[specificModel];
    if (allowedTiers && !allowedTiers.includes(sec.userTier)) {
      return res.status(403).json({ error: `Model ${specificModel} requires: ${allowedTiers.join(', ')} tier`, required: allowedTiers, current: sec.userTier });
    }

    const githubToken = req.headers['x-github-token'];
    const extraHeaders = {};
    if (githubToken) extraHeaders['X-GitHub-Token'] = githubToken;

    try {
      const result = await callProvider(modelConfig.provider, modelConfig.model, messages, stream, extraHeaders);
      return respondWithResult(res, result, stream, req, version, sec);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // v4: auto-select or use model from body
  if (version === 4) {
    const reqModel = model || 'auto';
    if (V4_MODELS[reqModel]) return handleChat(req, res, 4, reqModel);
    try {
      const result = await autoRoute(reqModel, messages, stream);
      return respondWithResult(res, result, stream, req, version, sec);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // v1/v2/v3: standard routing
  const versionConfig = VERSION_MODELS[version];
  const apiModel = model || versionConfig.defaultModel;

  // Extract GitHub token for GitHub Models routing
  const githubToken = req.headers['x-github-token'];
  const extraHeaders = {};
  if (githubToken) extraHeaders['X-GitHub-Token'] = githubToken;

  if (version === 2) {
    const proModel = model || 'z-ai/glm-4.7-flash-free';
    try {
      const result = await autoRoute(proModel, messages, stream, extraHeaders);
      return respondWithResult(res, result, stream, req, version, sec);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  if (version === 3) {
    const ultraModel = model || 'z-ai/glm-5.1';
    try {
      const result = await autoRoute(ultraModel, messages, stream, extraHeaders);
      return respondWithResult(res, result, stream, req, version, sec);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // v1: DeepCode Go (default, auto model)
  try {
    const result = await autoRoute(apiModel, messages, stream, extraHeaders);
    return respondWithResult(res, result, stream, req, version, sec);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
}

// ===== Models Handler =====
function handleModels(req, res) {
  const models = Object.entries(VERSION_MODELS).map(([v, c]) => ({
    version: parseInt(v),
    label: c.label,
    defaultModel: c.defaultModel,
  }));

  const v4Models = Object.entries(V4_MODELS).map(([id, m]) => ({
    id,
    name: m.name,
    provider: m.provider,
    model: m.model,
    tiers: V4_TIER_RESTRICTED[id] || [],
  }));

  return res.json({ models, v4Models, providers: Object.keys(PROVIDERS) });
}

// ===== Health Check Handler =====
function handleHealth(req, res) {
  const providers = {};
  for (const [name, p] of Object.entries(PROVIDERS)) {
    providers[name] = { hasKeys: p.keys.length > 0, priority: p.priority };
  }
  return res.json({ status: 'ok', timestamp: new Date().toISOString(), providers });
}

// ===== Export =====
module.exports = async function handler(req, res) {
  if (handleCors(res, req)) return;

  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const pathParts = url.pathname.split('/').filter(Boolean);

  // GET endpoints
  if (req.method === 'GET') {
    const adminSecret = req.headers['x-admin-secret'];

    // Health check
    if (pathParts.includes('health')) return handleHealth(req, res);

    // Models
    if (pathParts.includes('models')) return handleModels(req, res);

    // Security admin: stats
    if (pathParts.includes('stats')) {
      if (!adminSecret || adminSecret !== process.env.GATEWAY_SECRET) return res.status(401).json({ error: 'Unauthorized' });
      return res.json(getSecurityStats());
    }

    // Security admin: audit
    if (pathParts.includes('audit')) {
      if (!adminSecret || adminSecret !== process.env.GATEWAY_SECRET) return res.status(401).json({ error: 'Unauthorized' });
      const limit = parseInt(url.searchParams.get('limit')) || 100;
      return res.json({ entries: getAuditLog(limit) });
    }

    return res.status(404).json({ error: 'Not found' });
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Parse version and optional model from URL
  let version = 1;
  let specificModel = null;
  if (pathParts[0] && pathParts[0].startsWith('v')) version = parseInt(pathParts[0].substring(1)) || 1;
  if (pathParts.length > 3 && pathParts[0].startsWith('v')) specificModel = pathParts[3];

  return handleChat(req, res, version, specificModel);
};
