const crypto = require('crypto');
const { verifyApiKey } = require('./api-keys');

// ===== Master Secret (ONLY exists on server, never in IDE) =====
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;
if (!GATEWAY_SECRET) {
  throw new Error('FATAL: GATEWAY_SECRET env var is required. Set it on Vercel!');
}

const MAX_AGE_MS = 30000;
const BINDING_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const SESSION_TOKEN_MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours
const RATE_LIMIT_MAX = 50;
const RATE_LIMIT_WINDOW_MS = 60000;
const IP_BLACKLIST_WINDOW_MS = 60 * 60 * 1000; // 1 hour
const IP_BLACKLIST_MAX_FAILURES = 5;

// ===== Global State =====
if (!global.__gatewayState) {
  global.__gatewayState = {
    rateLimits: new Map(),
    ipFailures: new Map(),
    ipBlacklist: new Set(),
    auditLog: [],
    sessionTokens: new Map(), // token -> { email, apiKey, deviceId, expiresAt }
  };
}
const state = global.__gatewayState;

// ===== Audit Logging =====
function auditLog(event, details) {
  const entry = { timestamp: new Date().toISOString(), event, ...details };
  state.auditLog.push(entry);
  if (state.auditLog.length > 1000) state.auditLog = state.auditLog.slice(-1000);
  if (['RATE_LIMIT_EXCEEDED', 'IP_BLACKLISTED', 'SIGNATURE_INVALID', 'BINDING_FORGERY', 'TIER_BYPASS_ATTEMPT', 'SESSION_FORGERY'].includes(event)) {
    console.warn(`[SECURITY] ${event}:`, JSON.stringify(details));
  }
}

// ===== HMAC Helpers =====
function hmacSign(secret, message) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// ===== Per-User Secret (derived from master secret + API key) =====
// hacker extracts IDE → gets ONE user's secret, NOT the master secret
function deriveUserSecret(apiKey) {
  return hmacSign(GATEWAY_SECRET, `user-secret:${apiKey}`);
}

// ===== Canonical JSON =====
function canonicalJson(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

// ===== Signature Verification (using per-user secret) =====
function verifySignature(signature, timestamp, bodyStr, deviceId, apiKey) {
  const now = Date.now();
  const ts = parseInt(timestamp);
  const age = now - ts;
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) {
    auditLog('SIGNATURE_EXPIRED', { deviceId, age, timestamp });
    return false;
  }

  // Derive per-user secret from API key
  const userSecret = deriveUserSecret(apiKey);
  const message = `${timestamp}:${deviceId}:${bodyStr}`;
  const expected = hmacSign(userSecret, message);
  const valid = timingSafeEqual(signature, expected);

  if (!valid) auditLog('SIGNATURE_INVALID', { deviceId, timestamp });
  return valid;
}

// ===== Session Token System =====
// Session token: HMAC(masterSecret, apiKey:deviceId:email:timestamp)
// Valid for 24 hours, bound to specific user+device
function generateSessionToken(apiKey, deviceId, email) {
  const timestamp = Date.now().toString();
  const message = `${apiKey}:${deviceId}:${email}:${timestamp}`;
  const token = hmacSign(GATEWAY_SECRET, `session:${message}`);
  const tokenData = {
    email,
    apiKey,
    deviceId,
    createdAt: parseInt(timestamp),
    expiresAt: Date.now() + SESSION_TOKEN_MAX_AGE_MS,
  };
  // Store in global state (persists within same Vercel instance)
  state.sessionTokens.set(token, tokenData);
  return { token, expiresAt: tokenData.expiresAt };
}

function verifySessionToken(token, apiKey, deviceId, email) {
  if (!token) return { valid: false, error: 'No session token' };

  const tokenData = state.sessionTokens.get(token);
  if (!tokenData) return { valid: false, error: 'Invalid session token' };

  // Check expiry
  if (Date.now() > tokenData.expiresAt) {
    state.sessionTokens.delete(token);
    return { valid: false, error: 'Session token expired' };
  }

  // Verify token matches expected HMAC
  const message = `${tokenData.apiKey}:${tokenData.deviceId}:${tokenData.email}:${tokenData.createdAt}`;
  const expected = hmacSign(GATEWAY_SECRET, `session:${message}`);
  const valid = timingSafeEqual(token, expected);

  if (!valid) {
    auditLog('SESSION_FORGERY', { email, apiKey: apiKey.substring(0, 10) });
    return { valid: false, error: 'Invalid session token' };
  }

  // Verify identity matches
  if (tokenData.email !== email || tokenData.apiKey !== apiKey || tokenData.deviceId !== deviceId) {
    return { valid: false, error: 'Session token does not match identity' };
  }

  return { valid: true };
}

// ===== Device Whitelist =====
const ALLOWED_DEVICES = new Set(['deepcode-ide-v1']);
function isDeviceAllowed(deviceId) { return ALLOWED_DEVICES.has(deviceId); }

// ===== IP Blacklist =====
function isIpBlacklisted(ip) {
  if (!ip || ip === 'unknown') return false;
  if (state.ipBlacklist.has(ip)) { auditLog('IP_BLACKLISTED_HIT', { ip }); return true; }
  return false;
}

function recordIpFailure(ip) {
  if (!ip || ip === 'unknown') return;
  const now = Date.now();
  const record = state.ipFailures.get(ip) || { count: 0, resetAt: now + IP_BLACKLIST_WINDOW_MS };
  if (now > record.resetAt) { record.count = 0; record.resetAt = now + IP_BLACKLIST_WINDOW_MS; }
  record.count++;
  state.ipFailures.set(ip, record);
  if (record.count >= IP_BLACKLIST_MAX_FAILURES) {
    state.ipBlacklist.add(ip);
    auditLog('IP_BLACKLISTED', { ip, failureCount: record.count });
    setTimeout(() => { state.ipBlacklist.delete(ip); state.ipFailures.delete(ip); }, IP_BLACKLIST_WINDOW_MS);
  }
}

function clearIpFailure(ip) { state.ipFailures.delete(ip); }

// ===== IP Consistency (IPv4 + IPv6) =====
function verifyIpConsistency(loginIp, currentIp) {
  if (!loginIp || !currentIp || currentIp === 'unknown') return { valid: true };
  if (loginIp === currentIp) return { valid: true };
  if (loginIp.includes('.')) {
    const loginSubnet = loginIp.split('.').slice(0, 3).join('.');
    const currentSubnet = currentIp.split('.').slice(0, 3).join('.');
    if (loginSubnet === currentSubnet) return { valid: true, warning: 'IP changed but same subnet' };
  }
  if (loginIp.includes(':')) {
    const loginPrefix = loginIp.split(':').slice(0, 4).join(':');
    const currentPrefix = currentIp.split(':').slice(0, 4).join(':');
    if (loginPrefix === currentPrefix) return { valid: true, warning: 'IP changed but same /64 prefix' };
  }
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
function verifyBindingSignature(bindingSig, deviceId, email, provider, loginIp, bindingTimestamp) {
  if (!bindingSig) return false;
  const message = `${deviceId}:${email}:${provider}:${loginIp}:${bindingTimestamp}`;
  const expected = hmacSign(GATEWAY_SECRET, message);
  const valid = timingSafeEqual(bindingSig, expected);
  if (!valid) auditLog('BINDING_FORGERY', { deviceId, email, provider });
  return valid;
}

// ===== Rate Limiter =====
function getRateLimitKey(apiKey, deviceId) {
  const hash = crypto.createHash('sha256').update(apiKey).digest('hex').substring(0, 16);
  return `${hash}:${deviceId}`;
}

function checkRateLimit(rateLimitKey, max = RATE_LIMIT_MAX, windowMs = RATE_LIMIT_WINDOW_MS) {
  const now = Date.now();
  const r = state.rateLimits.get(rateLimitKey) || { count: 0, resetAt: now + windowMs };
  if (now > r.resetAt) { r.count = 0; r.resetAt = now + windowMs; }
  r.count++;
  state.rateLimits.set(rateLimitKey, r);
  const allowed = r.count <= max;
  if (!allowed) auditLog('RATE_LIMIT_EXCEEDED', { rateLimitKey, count: r.count, max });
  return allowed;
}

// ===== Tier Verification =====
const TIER_MIN_VERSIONS = { free: 1, pro: 2, premium: 3, business: 4, ultra: 4 };
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

// ===== Full Security Check =====
async function securityCheck(req, version) {
  const result = { ok: false, error: '', status: 200 };

  if (!GATEWAY_SECRET) { result.error = 'Server misconfigured'; result.status = 500; return result; }

  // 1. API Key verification
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) { auditLog('API_KEY_MISSING', { ip: getClientIp(req) }); result.error = 'Missing API key'; result.status = 401; return result; }

  const keyData = await verifyApiKey(apiKey);
  if (!keyData) { const ip = getClientIp(req); recordIpFailure(ip); auditLog('API_KEY_INVALID', { ip }); result.error = 'Invalid API key'; result.status = 401; return result; }

  // 2. IP blacklist
  const clientIp = getClientIp(req);
  if (isIpBlacklisted(clientIp)) { result.error = 'IP temporarily blocked'; result.status = 429; return result; }

  // 3. Device info
  const deviceId = req.headers['x-device-id'];
  const platform = req.headers['x-platform'];
  const versionHeader = req.headers['x-version'];
  if (!deviceId || !platform || !versionHeader) { result.error = 'Missing device info'; result.status = 401; return result; }
  if (!isDeviceAllowed(deviceId)) { auditLog('DEVICE_NOT_ALLOWED', { deviceId, apiKey: apiKey.substring(0, 10), ip: clientIp }); result.error = 'Device not registered'; result.status = 403; return result; }

  // 4. User identity
  const userEmail = keyData.email;
  const userProvider = keyData.provider || 'unknown';
  const userTier = keyData.tier || 'free';

  // 5. Session token (v2+ mandatory, v1 optional)
  const sessionToken = req.headers['x-session-token'];
  const bindingSig = req.headers['x-binding-signature'];
  const bindingTimestamp = req.headers['x-binding-timestamp'];
  const loginIp = req.headers['x-login-ip'];

  if (version >= 2) {
    // v2+: session token required
    if (!sessionToken) {
      // Fallback to binding signature
      if (!bindingSig || !bindingTimestamp || !loginIp) {
        auditLog('BINDING_MISSING', { deviceId, apiKey: apiKey.substring(0, 10), userEmail, version, ip: clientIp });
        result.error = 'Authentication required. Please login.'; result.status = 403; return result;
      }
      const validBinding = verifyBindingSignature(bindingSig, deviceId, userEmail, userProvider || '', loginIp || '', bindingTimestamp);
      if (!validBinding) { result.error = 'Invalid binding signature'; result.status = 403; return result; }
    } else {
      // Verify session token
      const tokenCheck = verifySessionToken(sessionToken, apiKey, deviceId, userEmail);
      if (!tokenCheck.valid) {
        result.error = tokenCheck.error; result.status = 403; return result;
      }
    }
  } else if (bindingSig && bindingTimestamp) {
    // v1: optional binding, verify if present
    const validBinding = verifyBindingSignature(bindingSig, deviceId, userEmail, userProvider || '', loginIp || '', bindingTimestamp);
    if (!validBinding) { auditLog('BINDING_FORGERY_V1', { deviceId, apiKey: apiKey.substring(0, 10), userEmail }); result.error = 'Invalid binding signature'; result.status = 403; return result; }
  }

  // 6. IP consistency
  if (loginIp) {
    const ipCheck = verifyIpConsistency(loginIp, clientIp);
    if (!ipCheck.valid) { result.error = ipCheck.error; result.status = 403; return result; }
  }

  // 7. Rate limit
  if (!checkRateLimit(getRateLimitKey(apiKey, deviceId))) {
    result.error = 'Rate limit exceeded (50 req/min)'; result.status = 429; return result;
  }

  // 8. HMAC Signature (using per-user secret derived from API key)
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];
  if (!timestamp || !signature) { result.error = 'Missing signature'; result.status = 401; return result; }

  let bodyStr;
  try { bodyStr = canonicalJson(req.body); } catch { result.error = 'Invalid body'; result.status = 400; return result; }

  if (!verifySignature(signature, timestamp, bodyStr, deviceId, apiKey)) {
    recordIpFailure(clientIp);
    auditLog('SIGNATURE_INVALID', { deviceId, apiKey: apiKey.substring(0, 10), ip: clientIp });
    result.error = 'Invalid signature'; result.status = 401; return result;
  }

  // 9. Tier access
  if (!canAccessVersion(userTier, version)) {
    auditLog('TIER_BYPASS_ATTEMPT', { deviceId, apiKey: apiKey.substring(0, 10), userEmail, userTier, requestedVersion: version });
    result.error = `Version v${version} requires ${getTierForVersion(version)} tier or higher`; result.status = 403; return result;
  }

  // 10. Request validation
  const { messages } = req.body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) { result.error = 'Messages required'; result.status = 400; return result; }
  if (bodyStr.length > 200000) { result.error = 'Request too large (max 200KB)'; result.status = 413; return result; }

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

// ===== Get audit log =====
function getAuditLog(limit = 100) { return state.auditLog.slice(-limit); }

// ===== Get security stats =====
function getSecurityStats() {
  return {
    rateLimitsActive: state.rateLimits.size,
    ipBlacklisted: state.ipBlacklist.size,
    ipFailures: state.ipFailures.size,
    sessionTokensActive: state.sessionTokens.size,
    auditLogEntries: state.auditLog.length,
    recentEvents: state.auditLog.slice(-10),
  };
}

module.exports = {
  GATEWAY_SECRET,
  MAX_AGE_MS,
  hmacSign,
  deriveUserSecret,
  generateSessionToken,
  verifySessionToken,
  verifySignature,
  canonicalJson,
  isDeviceAllowed,
  checkRateLimit,
  canAccessVersion,
  getTierForVersion,
  securityCheck,
  getClientIp,
  verifyBindingSignature,
  TIER_ORDER,
  isIpBlacklisted,
  recordIpFailure,
  getAuditLog,
  getSecurityStats,
};
