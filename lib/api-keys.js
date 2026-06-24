const crypto = require('crypto');

// ===== Upstash Redis via REST API (no package needed) =====
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redisCommand(command, ...args) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
  try {
    const res = await fetch(UPSTASH_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${UPSTASH_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify([command, ...args]),
    });
    const data = await res.json();
    return data.result;
  } catch (e) {
    console.error('Redis error:', e.message);
    return null;
  }
}

// ===== In-memory fallback =====
const apiKeys = new Map();

// ===== Generate new API key =====
async function generateApiKey(email, tier = 'free') {
  const key = 'dc-' + crypto.randomBytes(20).toString('hex');
  const keyData = { email, tier, createdAt: Date.now(), lastUsedAt: null };

  const redisResult = await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
  if (redisResult !== null) {
    await redisCommand('SADD', `userkeys:${email}`, key);
  } else {
    apiKeys.set(key, keyData);
  }
  return { key, ...keyData };
}

// ===== Verify API key (no Redis write — read only) =====
async function verifyApiKey(key) {
  if (!key || !key.startsWith('dc-')) return null;

  let keyData;
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (raw !== null) {
    keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } else {
    keyData = apiKeys.get(key);
  }
  return keyData || null;
}

// ===== Update lastUsedAt (called separately, not on every verify) =====
async function touchApiKey(key) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (!raw) return;
  const keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  keyData.lastUsedAt = Date.now();
  await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
}

// ===== Revoke API key =====
async function revokeApiKey(key) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (raw) {
    const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
    await redisCommand('SREM', `userkeys:${data.email}`, key);
  }
  await redisCommand('DEL', `apikey:${key}`);
  return true;
}

// ===== List all API keys for a user =====
async function listApiKeys(email) {
  const result = [];
  const keyList = await redisCommand('SMEMBERS', `userkeys:${email}`) || [];
  for (const key of keyList) {
    const raw = await redisCommand('GET', `apikey:${key}`);
    if (raw) {
      const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
      result.push({ key: key.substring(0, 10) + '...', ...data });
    }
  }
  return result;
}

// ===== Update tier =====
async function updateKeyTier(key, tier) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (!raw) return false;
  const keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  keyData.tier = tier;
  await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
  return true;
}

// ===== Get token usage =====
async function getTokenUsage(key) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (!raw) return null;
  const keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  return {
    tokensUsed: keyData.tokensUsed || 0,
    tokensLimit: keyData.tokensLimit || 0,
    requestsToday: keyData.requestsToday || 0,
    lastResetAt: keyData.lastResetAt || null,
  };
}

// ===== Track token usage =====
async function trackTokenUsage(key, tokens) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (!raw) return;
  const keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  const today = new Date().toDateString();
  if (!keyData.lastResetAt || keyData.lastResetAt !== today) {
    keyData.tokensUsed = 0;
    keyData.requestsToday = 0;
    keyData.lastResetAt = today;
  }
  keyData.tokensUsed = (keyData.tokensUsed || 0) + tokens;
  keyData.requestsToday = (keyData.requestsToday || 0) + 1;
  await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
}

// ===== Check if Redis is available =====
function isRedisAvailable() { return !!(UPSTASH_URL && UPSTASH_TOKEN); }

module.exports = {
  generateApiKey,
  verifyApiKey,
  touchApiKey,
  revokeApiKey,
  listApiKeys,
  updateKeyTier,
  getTokenUsage,
  trackTokenUsage,
  isRedisAvailable,
};
