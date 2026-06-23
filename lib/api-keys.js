const crypto = require('crypto');

// ===== Vercel KV or in-memory fallback =====
let kv = null;
try {
  if (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) {
    kv = require('@vercel/kv');
  }
} catch {}

// ===== In-memory fallback (used when KV not available) =====
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
  
  if (kv) {
    await kv.set(`apikey:${key}`, JSON.stringify(keyData));
  } else {
    apiKeys.set(key, keyData);
  }
  
  return { key, ...keyData };
}

// ===== Verify API key =====
async function verifyApiKey(key) {
  if (!key || !key.startsWith('dc-')) return null;
  
  let keyData;
  if (kv) {
    const raw = await kv.get(`apikey:${key}`);
    keyData = raw ? JSON.parse(raw) : null;
  } else {
    keyData = apiKeys.get(key);
  }
  
  if (!keyData) return null;
  
  // Update last used
  keyData.lastUsedAt = Date.now();
  keyData.requestCount++;
  
  if (kv) {
    await kv.set(`apikey:${key}`, JSON.stringify(keyData));
  } else {
    apiKeys.set(key, keyData);
  }
  
  return keyData;
}

// ===== Revoke API key =====
async function revokeApiKey(key) {
  if (kv) {
    await kv.del(`apikey:${key}`);
  } else {
    apiKeys.delete(key);
  }
  return true;
}

// ===== List all API keys for a user =====
async function listApiKeys(email) {
  const result = [];
  
  if (kv) {
    // Scan for all apikey:* keys (Vercel KV doesn't support scan, so we need to track separately)
    const keyList = await kv.get(`userkeys:${email}`) || [];
    for (const key of keyList) {
      const raw = await kv.get(`apikey:${key}`);
      if (raw) {
        const data = JSON.parse(raw);
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
  
  if (kv) {
    const raw = await kv.get(`apikey:${key}`);
    keyData = raw ? JSON.parse(raw) : null;
  } else {
    keyData = apiKeys.get(key);
  }
  
  if (!keyData) return false;
  
  keyData.tier = tier;
  
  if (kv) {
    await kv.set(`apikey:${key}`, JSON.stringify(keyData));
  } else {
    apiKeys.set(key, keyData);
  }
  
  return true;
}

module.exports = {
  generateApiKey,
  verifyApiKey,
  revokeApiKey,
  listApiKeys,
  updateKeyTier,
};
