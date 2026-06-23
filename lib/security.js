const crypto = require('crypto');
const { verifyApiKey } = require('./api-keys');

// ===== Gateway credentials =====
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dc-c91d93094cd58202a0230fab112432f7833111f7';

if (!process.env.GATEWAY_SECRET) {
  console.warn('SECURITY: Using hardcoded fallback secret. Set GATEWAY_SECRET env var on Vercel!');
}

const MAX_AGE_MS = 30000;
const BINDING_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const RATE_LIMIT_MAX = 50;
const RATE_LIMIT_WINDOW_MS = 60000;
const IP_BLACKLIST_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const IP_BLACKLIST_MAX_FAILURES = 5;

// ===== Global State (persists within same Vercel instance) =====
// eslint-disable-next-line no-global-assign
if (!global.__gatewayState) {
  global.__gatewayState = {
    rateLimits: new Map(),
    ipFailures: new Map(),      // IP -> { count, resetAt }
    ipBlacklist: new Set(),      // IPs blocked temporarily
    auditLog: [],                // Recent security events
    suspiciousIPs: new Map(),    // IP -> { attempts, lastAttempt }
  };
}
const state = global.__gatewayState;

// ===== Audit Logging =====
function auditLog(event, details) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    ...details,
  };
  state.auditLog.push(entry);
  // Keep last 1000 entries
  if (state.auditLog.length > 1000) {
    state.auditLog = state.auditLog.slice(-1000);
  }
  // Log critical events to console
  if (['RATE_LIMIT_EXCEEDED', 'IP_BLACKLISTED', 'SIGNATURE_INVALID', 'BINDING_FORGERY', 'TIER_BYPASS_ATTEMPT'].includes(event)) {
    console.warn(`[SECURITY] ${event}:`, JSON.stringify(details));
  }
}

// ===== HMAC Signature =====
function hmacSign(secret, message) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function verifySignature(signature, timestamp, bodyStr, deviceId) {
  const now = Date.now();
  const ts = parseInt(timestamp);
  const age = now - ts;
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) {
    auditLog('SIGNATURE_EXPIRED', { deviceId, age, timestamp });
    return false;
  }
  const message = `${timestamp}:${deviceId}:${bodyStr}`;
  const expected = hmacSign(GATEWAY_SECRET, message);
  const valid = signature === expected;
  if (!valid) {
    auditLog('SIGNATURE_INVALID', { deviceId, timestamp });
  }
  return valid;
}

// ===== Canonical JSON: sorted keys, no spaces =====
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

// ===== IP Blacklist =====
function isIpBlacklisted(ip) {
  if (!ip || ip === 'unknown') return false;
  if (state.ipBlacklist.has(ip)) {
    auditLog('IP_BLACKLISTED_HIT', { ip });
    return true;
  }
  return false;
}

function recordIpFailure(ip) {
  if (!ip || ip === 'unknown') return;
  const now = Date.now();
  const record = state.ipFailures.get(ip) || { count: 0, resetAt: now + IP_BLACKLIST_WINDOW_MS };
  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + IP_BLACKLIST_WINDOW_MS;
  }
  record.count++;
  state.ipFailures.set(ip, record);
  if (record.count >= IP_BLACKLIST_MAX_FAILURES) {
    state.ipBlacklist.add(ip);
    auditLog('IP_BLACKLISTED', { ip, failureCount: record.count });
    // Auto-remove after window
    setTimeout(() => {
      state.ipBlacklist.delete(ip);
      state.ipFailures.delete(ip);
    }, IP_BLACKLIST_WINDOW_MS);
  }
}

function clearIpFailure(ip) {
  state.ipFailures.delete(ip);
}

// ===== IP Consistency =====
function verifyIpConsistency(loginIp, currentIp) {
  if (!loginIp || !currentIp || currentIp === 'unknown') return { valid: true };
  if (loginIp === currentIp) return { valid: true };
  const loginSubnet = loginIp.split('.').slice(0, 3).join('.');
  const currentSubnet = currentIp.split('.').slice(0, 3).join('.');
  if (loginSubnet === currentSubnet) return { valid: true, warning: 'IP changed but same subnet' };
  auditLog('IP_MISMATCH', { loginIp, currentIp });
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
  const valid = bindingSig === expected;
  if (!valid) {
    auditLog('BINDING_FORGERY', { deviceId, email, provider });
  }
  return valid;
}

// ===== Rate Limiter (global Map persists within instance) =====
function checkRateLimit(deviceId, max = RATE_LIMIT_MAX, windowMs = RATE_LIMIT_WINDOW_MS) {
  const now = Date.now();
  const r = state.rateLimits.get(deviceId) || { count: 0, resetAt: now + windowMs };
  if (now > r.resetAt) { r.count = 0; r.resetAt = now + windowMs; }
  r.count++;
  state.rateLimits.set(deviceId, r);
  const allowed = r.count <= max;
  if (!allowed) {
    auditLog('RATE_LIMIT_EXCEEDED', { deviceId, count: r.count, max });
  }
  return allowed;
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

  // 0. Secret check
  if (!GATEWAY_SECRET) {
    result.error = 'Server misconfigured'; result.status = 500; return result;
  }

  // 1. API Key verification (each user has unique key)
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) {
    auditLog('API_KEY_MISSING', { ip: getClientIp(req) });
    result.error = 'Missing API key'; result.status = 401; return result;
  }

  const keyData = verifyApiKey(apiKey);
  if (!keyData) {
    const ip = getClientIp(req);
    recordIpFailure(ip);
    auditLog('API_KEY_INVALID', { ip });
    result.error = 'Invalid API key'; result.status = 401; return result;
  }

  // 2. IP blacklist check
  const clientIp = getClientIp(req);
  if (isIpBlacklisted(clientIp)) {
    result.error = 'IP temporarily blocked due to repeated failures'; result.status = 429; return result;
  }

  // 3. Device info
  const deviceId = req.headers['x-device-id'];
  const platform = req.headers['x-platform'];
  const versionHeader = req.headers['x-version'];
  if (!deviceId || !platform || !versionHeader) {
    result.error = 'Missing device info'; result.status = 401; return result;
  }
  if (!isDeviceAllowed(deviceId)) {
    auditLog('DEVICE_NOT_ALLOWED', { deviceId, apiKey: apiKey.substring(0, 10), ip: clientIp });
    result.error = 'Device not registered'; result.status = 403; return result;
  }

  // 4. User identity from API key
  const userEmail = keyData.email;
  const userProvider = keyData.provider || 'unknown';
  const userTier = keyData.tier || 'free';

  // 5. Binding signature — REQUIRED for v2+
  const bindingSig = req.headers['x-binding-signature'];
  const bindingTimestamp = req.headers['x-binding-timestamp'];
  const loginIp = req.headers['x-login-ip'];

  if (version >= 2) {
    // Binding required for premium versions
    if (!bindingSig || !bindingTimestamp || !loginIp) {
      auditLog('BINDING_MISSING', { deviceId, apiKey: apiKey.substring(0, 10), userEmail, version, ip: clientIp });
      result.error = 'Authentication required for this version. Please login.'; result.status = 403; return result;
    }
    const validBinding = verifyBindingSignature(bindingSig, deviceId, userEmail, userProvider || '', loginIp || '', bindingTimestamp);
    if (!validBinding) {
      result.error = 'Invalid binding signature'; result.status = 403; return result;
    }
    const bindingAge = Date.now() - parseInt(bindingTimestamp);
    if (isNaN(bindingAge) || bindingAge > BINDING_MAX_AGE_MS) {
      auditLog('BINDING_EXPIRED', { deviceId, apiKey: apiKey.substring(0, 10), userEmail });
      result.error = 'Binding expired. Please re-login.'; result.status = 403; return result;
    }
  } else if (bindingSig && bindingTimestamp) {
    // v1: optional binding, but verify if present
    const validBinding = verifyBindingSignature(bindingSig, deviceId, userEmail, userProvider || '', loginIp || '', bindingTimestamp);
    if (!validBinding) {
      auditLog('BINDING_FORGERY_V1', { deviceId, apiKey: apiKey.substring(0, 10), userEmail });
      result.error = 'Invalid binding signature'; result.status = 403; return result;
    }
  }

  // 6. IP consistency (if binding present)
  if (loginIp) {
    const ipCheck = verifyIpConsistency(loginIp, clientIp);
    if (!ipCheck.valid) {
      result.error = ipCheck.error; result.status = 403; return result;
    }
  }

  // 7. Rate limit (by API key + device ID)
  if (!checkRateLimit(`${apiKey.substring(0, 10)}:${deviceId}`)) {
    result.error = 'Rate limit exceeded (50 req/min)'; result.status = 429; return result;
  }

  // 8. HMAC Signature (the REAL authentication)
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
    recordIpFailure(clientIp);
    auditLog('SIGNATURE_INVALID', { deviceId, apiKey: apiKey.substring(0, 10), ip: clientIp });
    result.error = 'Invalid signature'; result.status = 401; return result;
  }

  // 9. Tier access for version
  if (!canAccessVersion(userTier, version)) {
    auditLog('TIER_BYPASS_ATTEMPT', { deviceId, apiKey: apiKey.substring(0, 10), userEmail, userTier, requestedVersion: version });
    result.error = `Version v${version} requires ${getTierForVersion(version)} tier or higher`; result.status = 403; return result;
  }

  // 10. Request validation
  const { messages } = req.body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    result.error = 'Messages required'; result.status = 400; return result;
  }
  if (bodyStr.length > 200000) {
    result.error = 'Request too large (max 200KB)'; result.status = 413; return result;
  }

  // Success — clear IP failure count
  clearIpFailure(clientIp);

  result.ok = true;
  result.apiKey = apiKey.substring(0, 10) + '...';
  result.userEmail = userEmail;
  result.userProvider = userProvider;
  result.userTier = userTier;
  result.clientIp = clientIp;
  result.loginIp = loginIp;
  result.bodyStr = bodyStr;
  return result;
}

// ===== Get audit log (for admin) =====
function getAuditLog(limit = 100) {
  return state.auditLog.slice(-limit);
}

// ===== Get security stats =====
function getSecurityStats() {
  return {
    rateLimitsActive: state.rateLimits.size,
    ipBlacklisted: state.ipBlacklist.size,
    ipFailures: state.ipFailures.size,
    auditLogEntries: state.auditLog.length,
    recentEvents: state.auditLog.slice(-10),
  };
}

module.exports = {
  GATEWAY_SECRET,
  MAX_AGE_MS,
  hmacSign,
  verifySignature,
  canonicalJson,
  isDeviceAllowed,
  checkRateLimit,
  canAccessVersion,
  getTierForVersion,
  tierCanAccessModel,
  securityCheck,
  getClientIp,
  verifyBindingSignature,
  TIER_ORDER,
  isIpBlacklisted,
  recordIpFailure,
  getAuditLog,
  getSecurityStats,
};
