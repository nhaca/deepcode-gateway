const crypto = require('crypto');

// ===== Upstash Redis via REST API =====
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redisCommand(command, ...args) {
  if (!UPSTASH_URL || !UPSTASH_TOKEN) return null;
  try {
    const res = await fetch(UPSTASH_URL, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify([command, ...args]),
    });
    const data = await res.json();
    return data.result;
  } catch (e) {
    console.error('Redis error:', e.message);
    return null;
  }
}

const apiKeys = new Map();

// ===== Tier Credit Limits (per day) =====
const TIER_CREDIT_LIMITS = {
  free: 1000,
  pro: 10000,
  premium: 100000,
  business: 999999999,
};

// ===== Generate API Key =====
async function generateApiKey(email, tier = 'free', provider = 'unknown') {
  const key = 'dc-' + crypto.randomBytes(20).toString('hex');
  const keyData = { email, tier, provider, createdAt: Date.now(), lastUsedAt: null };
  const redisResult = await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
  if (redisResult !== null) {
    await redisCommand('SADD', `userkeys:${email}`, key);
    // Initialize credits
    const limit = TIER_CREDIT_LIMITS[tier] || TIER_CREDIT_LIMITS.free;
    await redisCommand('SET', `credits:${key}`, JSON.stringify({ remaining: limit, limit, resetAt: getTomorrowTimestamp() }));
  } else {
    apiKeys.set(key, keyData);
  }
  return { key, ...keyData };
}

function getTomorrowTimestamp() {
  const now = new Date();
  now.setHours(24, 0, 0, 0);
  return now.getTime();
}

// ===== Verify API Key (read only) =====
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

// ===== Touch API Key (update lastUsedAt) =====
async function touchApiKey(key) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (!raw) return;
  const keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  keyData.lastUsedAt = Date.now();
  await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
}

// ===== Credit System =====
async function getCredits(apiKey) {
  const raw = await redisCommand('GET', `credits:${apiKey}`);
  if (!raw) return { remaining: 1000, limit: 1000, resetAt: getTomorrowTimestamp() };
  const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  // Reset if past midnight
  if (Date.now() > data.resetAt) {
    const newLimit = data.limit;
    data.remaining = newLimit;
    data.resetAt = getTomorrowTimestamp();
    await redisCommand('SET', `credits:${apiKey}`, JSON.stringify(data));
  }
  return data;
}

async function useCredits(apiKey, amount) {
  const credits = await getCredits(apiKey);
  if (credits.remaining < amount) return false;
  credits.remaining -= amount;
  await redisCommand('SET', `credits:${apiKey}`, JSON.stringify(credits));
  return true;
}

async function addCredits(apiKey, amount) {
  const credits = await getCredits(apiKey);
  credits.remaining = Math.min(credits.remaining + amount, credits.limit);
  await redisCommand('SET', `credits:${apiKey}`, JSON.stringify(credits));
  return credits;
}

// ===== Update Tier (and credit limit) =====
async function updateKeyTier(key, tier) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (!raw) return false;
  const keyData = typeof raw === 'string' ? JSON.parse(raw) : raw;
  keyData.tier = tier;
  await redisCommand('SET', `apikey:${key}`, JSON.stringify(keyData));
  // Update credit limit
  const limit = TIER_CREDIT_LIMITS[tier] || TIER_CREDIT_LIMITS.free;
  const creditsRaw = await redisCommand('GET', `credits:${key}`);
  const credits = creditsRaw ? (typeof creditsRaw === 'string' ? JSON.parse(creditsRaw) : creditsRaw) : {};
  credits.limit = limit;
  credits.remaining = Math.min(credits.remaining || 0, limit);
  credits.resetAt = getTomorrowTimestamp();
  await redisCommand('SET', `credits:${key}`, JSON.stringify(credits));
  return true;
}

// ===== Revoke =====
async function revokeApiKey(key) {
  const raw = await redisCommand('GET', `apikey:${key}`);
  if (raw) {
    const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
    await redisCommand('SREM', `userkeys:${data.email}`, key);
  }
  await redisCommand('DEL', `apikey:${key}`);
  await redisCommand('DEL', `credits:${key}`);
  return true;
}

// ===== List Keys =====
async function listApiKeys(email) {
  const result = [];
  const keyList = await redisCommand('SMEMBERS', `userkeys:${email}`) || [];
  for (const key of keyList) {
    const raw = await redisCommand('GET', `apikey:${key}`);
    if (raw) {
      const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
      const credits = await getCredits(key);
      result.push({ key: key.substring(0, 10) + '...', ...data, credits });
    }
  }
  return result;
}

// ===== Token Usage Tracking =====
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

function isRedisAvailable() { return !!(UPSTASH_URL && UPSTASH_TOKEN); }

module.exports = {
  generateApiKey, verifyApiKey, touchApiKey, revokeApiKey, listApiKeys,
  updateKeyTier, getCredits, useCredits, addCredits, trackTokenUsage,
  isRedisAvailable, TIER_CREDIT_LIMITS,
};
