const crypto = require('crypto');

// ===== Upstash Redis (persistent across Vercel instances) =====
let redis = null;
try {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    const { Redis } = require('@upstash/redis');
    redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });
  }
} catch (e) {
  console.warn('Upstash Redis not available, using in-memory fallback');
}

// ===== In-memory fallback (used when Redis not available) =====
const apiKeys = new Map();

// ===== Generate new API key =====
async function generateApiKey(email, tier = 'free') {
  const key = 'dc-' + crypto.randomBytes(20).toString('hex');
  const keyData = {
    email,
    tier,
    createdAt: Date.now(),
    lastUsedAt: null,
    requestCount: 0,
  };
  
  if (redis) {
    await redis.set(`apikey:${key}`, JSON.stringify(keyData));
    // Track keys per user for listing
    const userKeys = await redis.get(`userkeys:${email}`) || [];
    if (!userKeys.includes(key)) {
      userKeys.push(key);
      await redis.set(`userkeys:${email}`, JSON.stringify(userKeys));
    }
  } else {
    apiKeys.set(key, keyData);
  }
  
  return { key, ...keyData };
}

// ===== Verify API key =====
async function verifyApiKey(key) {
  if (!key || !key.startsWith('dc-')) return null;
  
  let keyData;
  if (redis) {
    const raw = await redis.get(`apikey:${key}`);
    keyData = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw) : null;
  } else {
    keyData = apiKeys.get(key);
  }
  
  if (!keyData) return null;
  
  // Update last used (skip counter to save Redis calls)
  keyData.lastUsedAt = Date.now();
  
  if (redis) {
    await redis.set(`apikey:${key}`, JSON.stringify(keyData));
  } else {
    apiKeys.set(key, keyData);
  }
  
  return keyData;
}

// ===== Revoke API key =====
async function revokeApiKey(key) {
  if (redis) {
    const raw = await redis.get(`apikey:${key}`);
    if (raw) {
      const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
      // Remove from user's key list
      const userKeys = await redis.get(`userkeys:${data.email}`) || [];
      const updated = userKeys.filter(k => k !== key);
      await redis.set(`userkeys:${data.email}`, JSON.stringify(updated));
    }
    await redis.del(`apikey:${key}`);
  } else {
    apiKeys.delete(key);
  }
  return true;
}

// ===== List all API keys for a user =====
async function listApiKeys(email) {
  const result = [];
  
  if (redis) {
    const keyList = await redis.get(`userkeys:${email}`) || [];
    for (const key of keyList) {
      const raw = await redis.get(`apikey:${key}`);
      if (raw) {
        const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
        result.push({ key: key.substring(0, 10) + '...', ...data });
      }
    }
  } else {
    for (const [key, data] of apiKeys.entries()) {
      if (data.email === email) {
        result.push({ key: key.substring(0, 10) + '...', ...data });
      }
    }
  }
  
  return result;
}

// ===== Update tier =====
async function updateKeyTier(key, tier) {
  let keyData;
  
  if (redis) {
    const raw = await redis.get(`apikey:${key}`);
    keyData = raw ? (typeof raw === 'string' ? JSON.parse(raw) : raw) : null;
  } else {
    keyData = apiKeys.get(key);
  }
  
  if (!keyData) return false;
  
  keyData.tier = tier;
  
  if (redis) {
    await redis.set(`apikey:${key}`, JSON.stringify(keyData));
  } else {
    apiKeys.set(key, keyData);
  }
  
  return true;
}

// ===== Check if Redis is available =====
function isRedisAvailable() {
  return redis !== null;
}

module.exports = {
  generateApiKey,
  verifyApiKey,
  revokeApiKey,
  listApiKeys,
  updateKeyTier,
  isRedisAvailable,
};
