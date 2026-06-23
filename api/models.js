const { GATEWAY_KEY } = require('../lib/security');

const V1_MODELS = [
  { id: 'auto', name: 'Auto (Best Available)' },
  { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash' },
  { id: 'llama-3.3-70b-versatile', name: 'Llama 3.3 70B' },
  { id: 'deepseek-ai/deepseek-v4-flash', name: 'DeepSeek V4' },
  { id: 'z-ai/glm-5.1', name: 'GLM 5.1' },
  { id: 'z-ai/glm-5.2', name: 'GLM 5.2 (Puter)' },
  { id: 'deepseek/deepseek-v4-pro', name: 'DeepSeek V4 Pro (Puter)' },
  { id: 'meta-llama/llama-4-maverick', name: 'Llama 4 Maverick (Puter)' },
  { id: 'qwen/qwen3.7-max', name: 'Qwen 3.7 Max (Puter)' },
  { id: 'google/gemma-4-31b-it', name: 'Gemma 4 (Puter)' },
];

const V2_MODELS = [
  { id: 'z-ai/glm-4.7-flash-free', name: 'GLM 4.7 Flash Free' },
  { id: 'z-ai/glm-5.2-free', name: 'GLM 5.2 Free' },
  { id: 'stepfun/step-3.7-flash-free', name: 'Step 3.7 Flash Free' },
  { id: 'auto', name: 'Auto' },
];

const V3_MODELS = [
  { id: 'z-ai/glm-5.1', name: 'GLM 5.1' },
  { id: 'auto', name: 'Auto' },
];

const V4_MODELS = [
  { id: 'claude-opus-4-8', name: 'Claude Opus 4.8', tier: 'pro' },
  { id: 'claude-sonnet-4', name: 'Claude Sonnet 4', tier: 'pro' },
  { id: 'gpt-5', name: 'GPT-5', tier: 'premium' },
  { id: 'gpt-4.1', name: 'GPT-4.1', tier: 'pro' },
  { id: 'deepseek-v4', name: 'DeepSeek V4', tier: 'pro' },
  { id: 'glm-5.1', name: 'GLM 5.1', tier: 'pro' },
  { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash', tier: 'pro' },
  { id: 'llama-4-maverick', name: 'Llama 4 Maverick', tier: 'pro' },
  { id: 'qwen-3-235b', name: 'Qwen 3 235B', tier: 'pro' },
  { id: 'auto', name: 'Auto', tier: 'free' },
];

const VERSION_MODELS = {
  1: V1_MODELS,
  2: V2_MODELS,
  3: V3_MODELS,
  4: V4_MODELS,
};

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  // Parse version from URL
  const url = new URL(req.url, 'http://localhost');
  const pathParts = url.pathname.split('/').filter(Boolean);
  let version = 1;
  if (pathParts[0] && pathParts[0].startsWith('v')) {
    version = parseInt(pathParts[0].substring(1)) || 1;
  }

  const models = VERSION_MODELS[version] || V1_MODELS;
  return res.json({
    object: 'list',
    data: models.map(m => ({
      id: m.id,
      name: m.name,
      object: 'model',
      owned_by: 'deepcode-gateway',
      tier: m.tier || 'free',
      version,
    })),
  });
};
