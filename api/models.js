const V1_MODELS = [
  { id: 'auto', name: 'DeepCode AI' },
  { id: 'llama-3.3-70b-versatile', name: 'Llama 3.3 70B (Groq)' },
  { id: 'llama-3.1-8b-instant', name: 'Llama 3.1 8B (Groq)' },
  { id: 'llama-3.3-70b', name: 'Llama 3.3 70B (Cerebras)' },
  { id: 'llama-3.1-8b', name: 'Llama 3.1 8B (Cerebras)' },
  { id: 'deepseek-chat', name: 'DeepSeek V3 (DeepSeek)' },
  { id: 'deepseek-reasoner', name: 'DeepSeek R1 (DeepSeek)' },
  { id: 'deepseek-ai/deepseek-v3-0324', name: 'DeepSeek V3 (Nvidia)' },
  { id: 'meta-llama/llama-4-maverick', name: 'Llama 4 Maverick (OpenRouter)' },
  { id: 'mistral-small-latest', name: 'Mistral Small (Mistral)' },
  { id: 'codestral-latest', name: 'Codestral (Mistral)' },
  { id: 'command-r', name: 'Command R (Cohere)' },
  { id: 'command-r-plus', name: 'Command R+ (Cohere)' },
  { id: 'venice-uncensored', name: 'Venice Uncensored' },
  { id: 'Qwen/Qwen3-8B', name: 'Qwen3 8B (SiliconFlow)' },
  { id: 'deepseek-ai/DeepSeek-V3', name: 'DeepSeek V3 (SiliconFlow)' },
  { id: 'kira-3.5-flash', name: 'Kira 3.5 Flash' },
  { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash (Google)' },
];

const V2_MODELS = [
  { id: 'z-ai/glm-5.1', name: 'GLM 5.1' },
  { id: 'z-ai/glm-4.7-flash-free', name: 'GLM 4.7 Flash Free' },
  { id: 'stepfun/step-3.7-flash-free', name: 'Step 3.7 Flash Free' },
  { id: 'auto', name: 'DeepCode AI' },
];

const V3_MODELS = [
  { id: 'z-ai/glm-5.2-free', name: 'GLM 5.2 Free' },
  { id: 'auto', name: 'DeepCode AI' },
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
  { id: 'kira-3.5-flash', name: 'Kira 3.5 Flash', tier: 'pro' },
  { id: 'kira-2.5-pro', name: 'Kira 2.5 Pro', tier: 'pro' },
  { id: 'auto', name: 'DeepCode AI', tier: 'free' },
];

const VERSION_MODELS = { 1: V1_MODELS, 2: V2_MODELS, 3: V3_MODELS, 4: V4_MODELS };

const { verifyApiKey } = require('../lib/api-keys');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });
  const keyData = await verifyApiKey(apiKey);
  if (!keyData) return res.status(401).json({ error: 'Invalid API key' });

  const url = new URL(req.url, 'http://localhost');
  const pathParts = url.pathname.split('/').filter(Boolean);
  let version = 1;
  if (pathParts[0] && pathParts[0].startsWith('v')) version = parseInt(pathParts[0].substring(1)) || 1;

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
