const crypto = require('crypto');

// ===== In-memory fallback (used when KV not available) =====
// In production, this should be Vercel KV
const apiKeys = new Map();

// ===== Generate new API key =====
function generateApiKey(email, tier = 'free') {
  // Format: dc-<40 hex chars>
  const key = 'dc-' + crypto.randomBytes(20).toString('hex');
  const keyData = {
    email,
    tier,
    createdAt: Date.now(),
    lastUsedAt: null,
    requestCount: 0,
  };
  apiKeys.set(key, keyData);
  return { key, ...keyData };
}

// ===== Verify API key =====
function verifyApiKey(key) {
  if (!key || !key.startsWith('dc-')) return null;
  const keyData = apiKeys.get(key);
  if (!keyData) return null;
  
  // Update last used
  keyData.lastUsedAt = Date.now();
  keyData.requestCount++;
  apiKeys.set(key, keyData);
  
  return keyData;
}

// ===== Revoke API key =====
function revokeApiKey(key) {
  return apiKeys.delete(key);
}

// ===== List all API keys for a user =====
function listApiKeys(email) {
  const result = [];
  for (const [key, data] of apiKeys.entries()) {
    if (data.email === email) {
      result.push({ key: key.substring(0, 10) + '...', ...data });
    }
  }
  return result;
}

// ===== Update tier =====
function updateKeyTier(key, tier) {
  const keyData = apiKeys.get(key);
  if (!keyData) return false;
  keyData.tier = tier;
  apiKeys.set(key, keyData);
  return true;
}

module.exports = {
  generateApiKey,
  verifyApiKey,
  revokeApiKey,
  listApiKeys,
  updateKeyTier,
};
