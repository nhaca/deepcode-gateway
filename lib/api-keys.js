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
  const keyData = {
    email,
    tier,
    createdAt: Date.now(),
    lastUsedAt: null,
  };
  
  const redisResult = await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
  if (redisResult !== null) {
    // Track keys per user
    await redisCommand('SADD', `userkeys:${email}`, key);
  } else {
    apiKeys.set(key, keyData);
  }
  
  return { key, ...keyData };
}

// ===== Verify API key =====
async function verifyApiKey(key) {
  if (!key || !key.startsWith('dc-')) return null;
  
  let keyData;
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (raw !== null) {
    keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } else {
    keyData = apiKeys.get(key);
  }
  
  if (!keyData) return null;
  
  // Update last used
  keyData.lastUsedAt = Date.now();
  await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
  
  return keyData;
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

// ===== Check if Redis is available =====
function isRedisAvailable() {
  return !!(UPSTASH_URL && UPSTASH_TOKEN);
}

module.exports = {
  generateApiKey,
  verifyApiKey,
  revokeApiKey,
  listApiKeys,
  updateKeyTier,
  isRedisAvailable,
};
