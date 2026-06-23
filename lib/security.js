const crypto = require('crypto');

const GATEWAY_KEY = process.env.GATEWAY_KEY || 'e0b61247433643bba1703400d38aac9be79df383beb14e0cb068271fc721d8b4';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'f390c1ac21494d6db9f53b3bd4db8bdcee2f9f218d584a81be062a0e6d7db30f';
const MAX_AGE_MS = 30000;

// ===== HMAC Signature =====
function hmacSign(secret, message) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function verifySignature(signature, timestamp, bodyStr, deviceId) {
  const age = Date.now() - parseInt(timestamp);
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) return false;
  const message = `${timestamp}:${deviceId}:${bodyStr}`;
  const expected = hmacSign(GATEWAY_SECRET, message);
  return signature === expected;
}

// Canonical JSON: sorted keys, no spaces
function canonicalJson(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

// ===== Device Whitelist =====
const ALLOWED_DEVICES = new Set(['deepcode-ide-v1']);

function isDeviceAllowed(deviceId) {
  return ALLOWED_DEVICES.has(deviceId);
}

// ===== IP Consistency =====
// Compare IP at login (sent by IDE) vs current request IP
function verifyIpConsistency(loginIp, currentIp) {
  if (!loginIp || !currentIp || currentIp === 'unknown') return { valid: true };
  if (loginIp === currentIp) return { valid: true };
  // Allow same /24 subnet
  const loginSubnet = loginIp.split('.').slice(0, 3).join('.');
  const currentSubnet = currentIp.split('.').slice(0, 3).join('.');
  if (loginSubnet === currentSubnet) return { valid: true, warning: 'IP changed but same subnet' };
  return { valid: false, error: 'IP address changed significantly. Please re-login.' };
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    return first.split(',')[0].trim();
  }
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

// ===== Binding Signature =====
// IDE signs: HMAC(secret, deviceId:email:provider:loginIp:bindingTimestamp)
function verifyBindingSignature(bindingSig, deviceId, email, provider, loginIp, bindingTimestamp) {
  if (!bindingSig) return false;
  const message = `${deviceId}:${email}:${provider}:${loginIp}:${bindingTimestamp}`;
  const expected = hmacSign(GATEWAY_SECRET, message);
  return bindingSig === expected;
}

// ===== Rate Limiter (in-memory, per-invocation) =====
const rateLimits = new Map();

function checkRateLimit(deviceId, max = 50, windowMs = 60000) {
  const now = Date.now();
  const r = rateLimits.get(deviceId) || { count: 0, resetAt: now + windowMs };
  if (now > r.resetAt) { r.count = 0; r.resetAt = now + windowMs; }
  r.count++;
  rateLimits.set(deviceId, r);
  return r.count <= max;
}

// ===== Tier Verification =====
const TIER_MIN_VERSIONS = {
  free: 1,
  pro: 2,
  premium: 3,
  business: 4,
  ultra: 4,
};

const TIER_ORDER = { free: 0, pro: 1, premium: 2, business: 3, ultra: 4 };

function canAccessVersion(tier, version) {
  const minVersion = TIER_MIN_VERSIONS[tier] || 1;
  return version >= minVersion;
}

function getTierForVersion(version) {
  for (const [tier, minVer] of Object.entries(TIER_MIN_VERSIONS)) {
    if (minVer === version) return tier;
  }
  return 'free';
}

function tierCanAccessModel(userTier, requiredTiers) {
  if (!requiredTiers || requiredTiers.length === 0) return true;
  return requiredTiers.includes(userTier);
}

// ===== Full Security Check =====
function securityCheck(req, version) {
  const result = { ok: false, error: '', status: 200 };

  // 1. API Key
  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    result.error = 'Unauthorized'; result.status = 401; return result;
  }

  // 2. Device info
  const deviceId = req.headers['x-device-id'];
  const platform = req.headers['x-platform'];
  const versionHeader = req.headers['x-version'];
  if (!deviceId || !platform || !versionHeader) {
    result.error = 'Missing device info'; result.status = 401; return result;
  }
  if (!isDeviceAllowed(deviceId)) {
    result.error = 'Device not registered'; result.status = 403; return result;
  }

  // 3. User identity (optional for v1 free tier — anonymous allowed)
  const userEmail = req.headers['x-user-email'] || 'anonymous';
  const userProvider = req.headers['x-user-provider'] || 'unknown';

  // 4. Binding signature (proves IDE legitimately bound this device to this email)
  const bindingSig = req.headers['x-binding-signature'];
  const bindingTimestamp = req.headers['x-binding-timestamp'];
  const loginIp = req.headers['x-login-ip'];
  if (bindingSig && bindingTimestamp) {
    const validBinding = verifyBindingSignature(bindingSig, deviceId, userEmail, userProvider || '', loginIp || '', bindingTimestamp);
    if (!validBinding) {
      result.error = 'Invalid binding signature'; result.status = 403; return result;
    }
    // Check binding age (must be within 30 days)
    const bindingAge = Date.now() - parseInt(bindingTimestamp);
    if (isNaN(bindingAge) || bindingAge > 30 * 24 * 60 * 60 * 1000) {
      result.error = 'Binding expired. Please re-login.'; result.status = 403; return result;
    }
  }

  // 5. IP consistency
  const clientIp = getClientIp(req);
  if (loginIp) {
    const ipCheck = verifyIpConsistency(loginIp, clientIp);
    if (!ipCheck.valid) {
      result.error = ipCheck.error; result.status = 403; return result;
    }
  }

  // 6. Rate limit
  if (!checkRateLimit(deviceId)) {
    result.error = 'Rate limit exceeded'; result.status = 429; return result;
  }

  // 7. Signature
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  if (!timestamp || !signature) {
    result.error = 'Missing signature'; result.status = 401; return result;
  }

  let bodyStr;
  try { bodyStr = canonicalJson(req.body); } catch {
    result.error = 'Invalid body'; result.status = 400; return result;
  }

  if (!verifySignature(signature, timestamp, bodyStr, deviceId)) {
    result.error = 'Invalid signature'; result.status = 401; return result;
  }

  // 8. Tier access for version
  const userTier = req.headers['x-user-tier'] || 'free';
  if (!canAccessVersion(userTier, version)) {
    result.error = `Version v${version} requires ${getTierForVersion(version)} tier or higher`; result.status = 403; return result;
  }

  // 9. Request validation
  const { messages } = req.body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    result.error = 'Messages required'; result.status = 400; return result;
  }
  if (bodyStr.length > 200000) {
    result.error = 'Request too large'; result.status = 413; return result;
  }

  result.ok = true;
  result.userEmail = userEmail;
  result.userProvider = userProvider;
  result.userTier = userTier;
  result.clientIp = clientIp;
  result.loginIp = loginIp;
  result.bodyStr = bodyStr;
  return result;
}

module.exports = {
  GATEWAY_KEY,
  GATEWAY_SECRET,
  MAX_AGE_MS,
  hmacSign,
  verifySignature,
  isDeviceAllowed,
  checkRateLimit,
  canAccessVersion,
  getTierForVersion,
  tierCanAccessModel,
  securityCheck,
  getClientIp,
  verifyBindingSignature,
  TIER_ORDER,
};
