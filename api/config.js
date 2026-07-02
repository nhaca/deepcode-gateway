/**
 * /config endpoint — SINGLE SOURCE OF TRUTH
 * 
 * Returns all models, tiers, limits, capabilities in one response
 * IDE fetches this on startup and caches locally
 */

const tiers = require('../lib/tiers');

// ===== Model Registry =====
// All available models with full metadata
const MODELS = [
  // === DeepCode Internal (routed via auto) ===
  { id: 'auto', name: 'DeepCode', tier: 'free', gatewayVersion: 'v1', provider: 'deepcode', capabilities: ['text'] },
  { id: 'deepcode-go', name: 'DeepCode 4.8', tier: 'free', gatewayVersion: 'v1', provider: 'deepcode', capabilities: ['text'] },
  { id: 'deepcode-pro', name: 'DeepCode 5.2', tier: 'free', gatewayVersion: 'v1', provider: 'deepcode', capabilities: ['text'] },
  { id: 'deepcode-ultra', name: 'DeepCode 5.5', tier: 'free', gatewayVersion: 'v1', provider: 'deepcode', capabilities: ['text'] },

  // === Free Models (CometAPI) ===
  { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5', tier: 'free', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 0.8, output: 4 } },

  // === Free Models (Other providers) ===
  { id: 'claude-sonnet-5-free', name: 'Claude Sonnet 5 Free', tier: 'free', gatewayVersion: 'v5', provider: 'zenmux', capabilities: ['text'] },
  { id: 'glm-5.2-free', name: 'GLM 5.2 Free', tier: 'free', gatewayVersion: 'v6', provider: 'glm5', capabilities: ['text'] },

  // === Pro Models (CometAPI) ===
  { id: 'claude-opus-4-7', name: 'Claude Opus 4.7', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 4, output: 20 } },
  { id: 'claude-opus-4-8', name: 'Claude Opus 4.8', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 4, output: 20 } },
  { id: 'claude-sonnet-5', name: 'Claude Sonnet 5', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 1.6, output: 8 } },
  { id: 'claude-sonnet-4', name: 'Claude Sonnet 4', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 2.4, output: 12 } },
  { id: 'gpt-5', name: 'GPT-5', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 1, output: 8 } },
  { id: 'gpt-4.1', name: 'GPT-4.1', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 1.6, output: 6.4 } },
  { id: 'gpt-4o', name: 'GPT-4o', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 2, output: 8 } },
  { id: 'deepseek-v4', name: 'DeepSeek V4', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text'], pricing: { input: 0.42, output: 0.83 } },
  { id: 'gemini-3-flash', name: 'Gemini 3 Flash', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 0.4, output: 2.4 } },
  { id: 'glm-5.2', name: 'GLM 5.2', tier: 'pro', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text'], pricing: { input: 1.12, output: 3.53 } },

  // === Premium Models ===
  { id: 'gpt-5.5', name: 'GPT-5.5', tier: 'premium', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 4, output: 24 } },
  { id: 'gpt-5.4', name: 'GPT-5.4', tier: 'premium', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 2, output: 12 } },
  { id: 'claude-opus-4-5', name: 'Claude Opus 4.5', tier: 'premium', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 4, output: 20 } },
  { id: 'gemini-3.1-pro', name: 'Gemini 3.1 Pro', tier: 'premium', gatewayVersion: 'v4', provider: 'comet', capabilities: ['text', 'vision'], pricing: { input: 1.6, output: 9.6 } },
  { id: 'z-ai/glm-5.2-free', name: 'GLM 5.2 Free', tier: 'premium', gatewayVersion: 'v3', provider: 'nvidia', capabilities: ['text'] },

  // === GitHub Models (user's own token) ===
  { id: 'github:gpt-4o', name: 'GPT-4o (GitHub)', tier: 'free', gatewayVersion: 'v1', provider: 'github', capabilities: ['text', 'vision'] },
  { id: 'github:gpt-4o-mini', name: 'GPT-4o Mini (GitHub)', tier: 'free', gatewayVersion: 'v1', provider: 'github', capabilities: ['text'] },
  { id: 'github:gpt-4.1', name: 'GPT-4.1 (GitHub)', tier: 'free', gatewayVersion: 'v1', provider: 'github', capabilities: ['text'] },
  { id: 'github:DeepSeek-R1', name: 'DeepSeek R1 (GitHub)', tier: 'free', gatewayVersion: 'v1', provider: 'github', capabilities: ['text'] },
  { id: 'github:Llama-4-Maverick-17B-128E-Instruct', name: 'Llama 4 Maverick (GitHub)', tier: 'free', gatewayVersion: 'v1', provider: 'github', capabilities: ['text'] },
];

// ===== Provider Config =====
const PROVIDERS = {
  comet: { name: 'CometAPI', priority: 1 },
  zenmux: { name: 'ZenMux', priority: 2 },
  glm5: { name: 'GLM5.app', priority: 3 },
  github: { name: 'GitHub Models', priority: 4 },
  nvidia: { name: 'NVIDIA', priority: 5 },
  deepcode: { name: 'DeepCode', priority: 6 },
};

// ===== Native thinking models (no <thinking> tag injection) =====
const NATIVE_THINKING_MODELS = ['deepseek-r1', 'deepseek-reasoner', 'o1', 'o3', 'o4', 'claude', 'mimo'];

// ===== Vision-capable model prefixes =====
const VISION_PREFIXES = ['gpt-4o', 'gpt-4.1', 'o3', 'o4', 'claude', 'gemini', 'deepseek-vl', 'llama-4', 'qwen-vl', 'glm-4v', 'glm-5'];

// ===== Effort-capable model prefixes =====
const EFFORT_PREFIXES = ['deepcode-pro', 'deepcode-ultra', 'opencode:', 'opencode/', 'github:', 'github/'];

// ===== Handler =====
function handleConfig(req, res) {
  return res.json({
    // Tier configuration
    tiers: tiers.TIERS,
    tierOrder: tiers.TIER_ORDER,
    tierNames: tiers.TIER_NAMES,
    credits: tiers.CREDITS,
    creditsDisplay: tiers.CREDITS_DISPLAY,
    tierCost: tiers.TIER_COST,
    context: tiers.CONTEXT,
    rateLimits: tiers.RATE_LIMITS,
    resetLimits: tiers.RESET_LIMITS,
    versionAccess: tiers.VERSION_ACCESS,

    // Models (single source of truth)
    models: MODELS,

    // Providers
    providers: PROVIDERS,

    // Model capabilities
    capabilities: {
      nativeThinking: NATIVE_THINKING_MODELS,
      visionPrefixes: VISION_PREFIXES,
      effortPrefixes: EFFORT_PREFIXES,
    },

    // Meta
    version: '1.0.0',
    updatedAt: Date.now(),
  });
}

module.exports = { handleConfig, MODELS, PROVIDERS };
