/**
 * quota.js — Server-side quota management
 *
 * Single source of truth for ALL usage/quota/rate-limit
 * Uses Upstash Redis for persistence
 * NO client-side quota enforcement — server decides everything
 */

const crypto = require('crypto');
const { CREDITS: TIER_CREDITS, CONTEXT: TIER_CONTEXT, RATE_LIMITS } = require('./tiers');

// ===== Redis helpers =====
const UPSTASH_URL = process.env.UPSTASH_REDIS_REST_URL;
const UPSTASH_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

async function redis(command, ...args) {
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
    console.error('[Quota] Redis error:', e.message);
    return null;
  }
}

// ===== Key patterns =====
const key = {
  quota: (identifier) => `quota:${identifier}`,           // quota:{deviceId} or quota:{apiKey}
  rateLimit: (identifier) => `ratelimit:${identifier}`,   // ratelimit:{deviceId}
  usage: (identifier) => `usage:${identifier}`,           // usage:{deviceId}:{month}
  tier: (apiKey) => `tier:${apiKey}`,                     // tier:{apiKey}
};

// ===== Quota lifecycle =====
function getNextMonthTimestamp() {
  const now = new Date();
  now.setMonth(now.getMonth() + 1, 1);
  now.setHours(0, 0, 0, 0);
  return now.getTime();
}

function getCurrentMonth() {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

// ===== Core functions =====

/**
 * Get or initialize quota for an identifier (deviceId or apiKey)
 */
async function getQuota(identifier, tier = 'free') {
  const raw = await redis('GET', key.quota(identifier));
  if (raw) {
    const data = typeof raw === 'string' ? JSON.parse(raw) : raw;
    // Check if month expired → reset
    if (Date.now() > data.resetAt) {
      const limit = TIER_CREDITS[tier] || TIER_CREDITS.free;
      data.remaining = limit;
      data.limit = limit;
      data.tier = tier;
      data.resetAt = getNextMonthTimestamp();
      data.month = getCurrentMonth();
      await redis('SET', key.quota(identifier), JSON.stringify(data), 'EX', 60 * 60 * 24 * 35); // 35 days TTL
    }
    // Always use current tier limit (not stored old value)
    data.limit = TIER_CREDITS[data.tier] || TIER_CREDITS.free;
    return data;
  }

  // Initialize new quota
  const limit = TIER_CREDITS[tier] || TIER_CREDITS.free;
  const data = {
    remaining: limit,
    limit,
    tier,
    resetAt: getNextMonthTimestamp(),
    month: getCurrentMonth(),
    createdAt: Date.now(),
  };
  await redis('SET', key.quota(identifier), JSON.stringify(data), 'EX', 60 * 60 * 24 * 35);
  return data;
}

/**
 * Check if request is allowed (has remaining quota)
 * Returns: { allowed, remaining, limit, tier, resetAt }
 */
async function checkQuota(identifier, tier = 'free') {
  const quota = await getQuota(identifier, tier);
  return {
    allowed: quota.remaining > 0,
    remaining: quota.remaining,
    limit: quota.limit,
    tier: quota.tier,
    resetAt: quota.resetAt,
    month: quota.month,
  };
}

/**
 * Increment usage (atomic via Redis DECR)
 * Returns: { allowed, remaining, limit }
 */
async function incrementUsage(identifier, amount = 1, tier = 'free') {
  const quotaKey = key.quota(identifier);

  // Atomic decrement
  const remaining = await redis('DECRBY', quotaKey + ':counter', amount);

  // Get current quota to check limits
  const quota = await getQuota(identifier, tier);

  if (remaining < 0) {
    // Over quota — set counter to 0
    await redis('SET', quotaKey + ':counter', '0');
    return { allowed: false, remaining: 0, limit: quota.limit, tier: quota.tier };
  }

  if (remaining > quota.limit) {
    // Shouldn't happen, but safety check
    await redis('SET', quotaKey + ':counter', String(quota.limit));
    return { allowed: false, remaining: 0, limit: quota.limit, tier: quota.tier };
  }

  return { allowed: remaining > 0, remaining, limit: quota.limit, tier: quota.tier };
}

/**
 * Rate limiting — sliding window counter
 * Returns: { allowed, remaining, resetIn }
 */
async function checkRateLimit(identifier, tier = 'free') {
  const limit = RATE_LIMITS[tier] || RATE_LIMITS.free;
  const windowMs = 60000; // 1 minute
  const now = Date.now();
  const windowStart = now - windowMs;

  const rlKey = key.rateLimit(identifier);

  // Remove old entries
  await redis('ZREMRANGEBYSCORE', rlKey, 0, windowStart);

  // Count current window
  const count = await redis('ZCARD', rlKey);

  if (count >= limit) {
    // Get oldest entry to calculate reset time
    const oldest = await redis('ZRANGE', rlKey, 0, 0, 'WITHSCORES');
    const resetIn = oldest && oldest[1] ? parseInt(oldest[1]) + windowMs - now : windowMs;
    return { allowed: false, remaining: 0, resetIn };
  }

  // Add current request
  await redis('ZADD', rlKey, now, `${now}-${crypto.randomBytes(4).toString('hex')}`);
  await redis('EXPIRE', rlKey, Math.ceil(windowMs / 1000) + 1);

  return { allowed: true, remaining: limit - count - 1, resetIn: windowMs };
}

/**
 * Middleware: enforce quota before processing request
 * Returns error response if quota exceeded, null if OK
 */
async function enforceQuota(identifier, tier = 'free') {
  // 1. Check quota
  const quota = await checkQuota(identifier, tier);
  if (!quota.allowed) {
    return {
      error: true,
      status: 429,
      message: `Hết quota tháng này. Còn lại: ${quota.remaining}/${quota.limit} tokens. Reset: ${new Date(quota.resetAt).toLocaleDateString()}`,
      quota,
    };
  }

  // 2. Check rate limit
  const rate = await checkRateLimit(identifier, tier);
  if (!rate.allowed) {
    return {
      error: true,
      status: 429,
      message: `Rate limit exceeded. Try again in ${Math.ceil(rate.resetIn / 1000)}s`,
      rateLimit: rate,
    };
  }

  return null; // OK
}

/**
 * Get usage stats for a user (for display)
 */
async function getUsageStats(identifier, tier = 'free') {
  const quota = await getQuota(identifier, tier);
  const rate = await checkRateLimit(identifier, tier);
  return {
    tier: quota.tier,
    tokensUsed: quota.limit - quota.remaining,
    tokensLimit: quota.limit,
    tokensRemaining: quota.remaining,
    resetAt: quota.resetAt,
    month: quota.month,
    rateLimitRemaining: rate.remaining,
  };
}

/**
 * Set tier for an API key (server-side only, requires payment verification)
 */
async function setTier(apiKey, newTier, paymentVerified = false) {
  if (!paymentVerified) {
    console.warn(`[Quota] Tier upgrade rejected: payment not verified for ${apiKey.slice(0, 12)}...`);
    return false;
  }

  if (!['free', 'pro', 'premium', 'business'].includes(newTier)) {
    return false;
  }

  const tierKey = key.tier(apiKey);
  await redis('SET', tierKey, newTier);

  // Update quota with new tier limit
  const quota = await getQuota(apiKey, newTier);
  quota.tier = newTier;
  quota.limit = TIER_CREDITS[newTier] || TIER_CREDITS.free;
  await redis('SET', key.quota(apiKey), JSON.stringify(quota), 'EX', 60 * 60 * 24 * 35);

  return true;
}

module.exports = {
  getQuota,
  checkQuota,
  incrementUsage,
  checkRateLimit,
  enforceQuota,
  getUsageStats,
  setTier,
  redis,
};
