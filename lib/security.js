const crypto = require('crypto');
const { verifyApiKey, getCredits, useCredits } = require('./api-keys');

// ===== Master Secret (ONLY on Vercel) =====
const GATEWAY_SECRET = process.env.GATEWAY_SECRET;
if (!GATEWAY_SECRET) console.warn('[SECURITY] GATEWAY_SECRET not set - security checks disabled');

const MAX_AGE_MS = 30000;
const BINDING_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const SESSION_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour (commercial grade)
const RATE_LIMIT_MAX = 50;
const RATE_LIMIT_WINDOW_MS = 60000;
const IP_BLACKLIST_WINDOW_MS = 60 * 60 * 1000;
const IP_BLACKLIST_MAX_FAILURES = 5;

// ===== Global State =====
if (!global.__gatewayState) {
  global.__gatewayState = {
    rateLimits: new Map(),
    ipFailures: new Map(),
    ipBlacklist: new Set(),
    auditLog: [],
    sessionTokens: new Map(),
  };
}
const state = global.__gatewayState;

// ===== Audit Logging =====
function auditLog(event, details) {
  const entry = { timestamp: new Date().toISOString(), event, ...details };
  state.auditLog.push(entry);
  if (state.auditLog.length > 1000) state.auditLog = state.auditLog.slice(-1000);
  if (['RATE_LIMIT_EXCEEDED', 'IP_BLACKLISTED', 'SIGNATURE_INVALID', 'BINDING_FORGERY',
       'TIER_BYPASS_ATTEMPT', 'SESSION_FORGERY', 'CREDIT_EXCEEDED', 'ANOMALY_DETECTED'].includes(event)) {
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

// ===== Per-User Secret =====
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

// ===== Signature Verification (per-user secret) =====
function verifySignature(signature, timestamp, bodyStr, deviceId, apiKey) {
  const now = Date.now();
  const ts = parseInt(timestamp);
  const age = now - ts;
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) {
    auditLog('SIGNATURE_EXPIRED', { deviceId, age, timestamp });
    return false;
  }
  const userSecret = deriveUserSecret(apiKey);
  const message = `${timestamp}:${deviceId}:${bodyStr}`;
  const expected = hmacSign(userSecret, message);
  const valid = timingSafeEqual(signature, expected);
  if (!valid) auditLog('SIGNATURE_INVALID', { deviceId, timestamp });
  return valid;
}

// ===== Session Token System (1 hour TTL) =====
function generateSessionToken(apiKey, deviceId, email) {
  const timestamp = Date.now().toString();
  const message = `${apiKey}:${deviceId}:${email}:${timestamp}`;
  const token = hmacSign(GATEWAY_SECRET, `session:${message}`);
  const tokenData = { email, apiKey, deviceId, createdAt: parseInt(timestamp), expiresAt: Date.now() + SESSION_TOKEN_TTL_MS };
  state.sessionTokens.set(token, tokenData);
  return { token, expiresAt: tokenData.expiresAt };
}

function verifySessionToken(token, apiKey, deviceId, email) {
  if (!token) return { valid: false, error: 'No session token' };
  const tokenData = state.sessionTokens.get(token);
  if (!tokenData) return { valid: false, error: 'Invalid session token' };
  if (Date.now() > tokenData.expiresAt) {
    state.sessionTokens.delete(token);
    return { valid: false, error: 'Session expired' };
  }
  const message = `${tokenData.apiKey}:${tokenData.deviceId}:${tokenData.email}:${tokenData.createdAt}`;
  const expected = hmacSign(GATEWAY_SECRET, `session:${message}`);
  const valid = timingSafeEqual(token, expected);
  if (!valid) { auditLog('SESSION_FORGERY', { email }); return { valid: false, error: 'Invalid session token' }; }
  if (tokenData.email !== email || tokenData.apiKey !== apiKey || tokenData.deviceId !== deviceId) {
    return { valid: false, error: 'Session identity mismatch' };
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

// ===== IP Consistency =====
function verifyIpConsistency(loginIp, currentIp) {
  if (!loginIp || !currentIp || currentIp === 'unknown') return { valid: true };
  if (loginIp === currentIp) return { valid: true };
  if (loginIp.includes('.')) {
    const s1 = loginIp.split('.').slice(0, 3).join('.');
    const s2 = currentIp.split('.').slice(0, 3).join('.');
    if (s1 === s2) return { valid: true, warning: 'Same subnet' };
  }
  if (loginIp.includes(':')) {
    const p1 = loginIp.split(':').slice(0, 4).join(':');
    const p2 = currentIp.split(':').slice(0, 4).join(':');
    if (p1 === p2) return { valid: true, warning: 'Same /64 prefix' };
  }
  auditLog('IP_MISMATCH', { loginIp, currentIp });
  return { valid: false, error: 'IP changed significantly. Please re-login.' };
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) { const first = Array.isArray(forwarded) ? forwarded[0] : forwarded; return first.split(',')[0].trim(); }
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
  return `${crypto.createHash('sha256').update(apiKey).digest('hex').substring(0, 16)}:${deviceId}`;
}

function checkRateLimit(key, max = RATE_LIMIT_MAX, windowMs = RATE_LIMIT_WINDOW_MS) {
  const now = Date.now();
  const r = state.rateLimits.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > r.resetAt) { r.count = 0; r.resetAt = now + windowMs; }
  r.count++;
  state.rateLimits.set(key, r);
  const allowed = r.count <= max;
  if (!allowed) auditLog('RATE_LIMIT_EXCEEDED', { key, count: r.count, max });
  return allowed;
}

// ===== Tier Verification =====
const TIER_MIN_VERSIONS = { free: 1, pro: 2, premium: 3, business: 4, ultra: 4 };
const TIER_ORDER = { free: 0, pro: 1, premium: 2, business: 3, ultra: 4 };

function canAccessVersion(tier, version) { return version >= (TIER_MIN_VERSIONS[tier] || 1); }
function getTierForVersion(version) {
  for (const [tier, minVer] of Object.entries(TIER_MIN_VERSIONS)) { if (minVer === version) return tier; }
  return 'free';
}

// ===== Anomaly Detection =====
function detectAnomalies(apiKey, clientIp, loginIp) {
  const anomalies = [];
  // IP mismatch beyond subnet
  if (loginIp && clientIp && loginIp !== clientIp) {
    if (loginIp.includes('.')) {
      const s1 = loginIp.split('.').slice(0, 2).join('.');
      const s2 = clientIp.split('.').slice(0, 2).join('.');
      if (s1 !== s2) anomalies.push('IP_CHANGED_SIGNIFICANTLY');
    }
  }
  // Check for rapid requests (possible bot)
  const rateKey = getRateLimitKey(apiKey, 'global');
  const rateData = state.rateLimits.get(rateKey);
  if (rateData && rateData.count > 40) anomalies.push('HIGH_REQUEST_RATE');
  if (anomalies.length > 0) {
    auditLog('ANOMALY_DETECTED', { apiKey: apiKey.substring(0, 10), clientIp, anomalies });
  }
  return anomalies;
}

// ===== Credit Cost per Model =====
const MODEL_CREDIT_COST = {
  // Free tier models
  'auto': 1, 'llama-3.3-70b-versatile': 1, 'llama-3.1-8b-instant': 1,
  'llama-3.3-70b': 1, 'llama-3.1-8b': 1, 'llama-3.1-70b-versatile': 1,
  'llama-3.1-70b': 1, 'gemma2-9b-it': 1, 'mixtral-8x7b-32768': 1,
  'DeepSeek-V3-0324': 1, 'Llama-3.3-70B': 1, 'Llama-3.1-8B': 1, 'Llama-3.1-70B': 1,
  'meta/llama-3.3-70b-instruct': 1, 'meta/llama-3.1-8b-instruct': 1, 'meta/llama-3.1-70b-instruct': 1,
  'deepseek-ai/deepseek-r1': 1, 'mistralai/mistral-large-2-instruct': 1,
  'openrouter:meta-llama/llama-3.3-70b-instruct': 1, 'openrouter:meta-llama/llama-3.1-8b-instruct': 1,
  'openrouter:meta-llama/llama-3.1-70b-instruct': 1, 'openrouter:mistralai/mistral-7b-instruct': 1,
  'openrouter:qwen/qwen-2.5-72b-instruct': 1, 'openrouter:google/gemma-2-9b-it': 1,
  'openrouter:anthropic/claude-3.5-sonnet': 1, 'openrouter:openai/gpt-4o-mini': 1,
  'openrouter:openai/gpt-4o': 1, 'openrouter:google/gemini-2.0-flash-001': 1,
  'mistral-small-latest': 1, 'mistral-large-latest': 1, 'codestral-latest': 1, 'open-mistral-nemo': 1,
  'command-r': 1, 'command-r-plus': 1, 'command-r-light': 1,
  'venice-uncensored': 1,
  'llm7:meta-llama/llama-3.3-70b-instruct': 1, 'llm7:meta-llama/llama-3.1-8b-instruct': 1,
  'huggingface:Qwen/Qwen3-8B': 1, 'huggingface:meta-llama/Llama-3.3-70B-Instruct': 1,
  'huggingface:meta-llama/Llama-3.1-8B-Instruct': 1,
  'kira-3.5-flash': 1, 'kira-2.5-pro': 1,
  'ovhcloud:meta-llama/Meta-Llama-3.3-70B-Instruct': 1, 'ovhcloud:meta-llama/Meta-Llama-3.1-8B-Instruct': 1,
  'gemini-2.5-flash': 1, 'gemini-2.0-flash': 1, 'gemini-1.5-flash': 1, 'gemini-1.5-pro': 1,
  // Mid-tier
  'z-ai/glm-5.1': 5, 'z-ai/glm-4.7-flash-free': 5, 'stepfun/step-3.7-flash-free': 5,
  'z-ai/glm-5.2-free': 5,
  // Premium
  'claude-opus-4-8': 20, 'claude-sonnet-4': 20, 'gpt-5': 20,
  'gpt-4.1': 15, 'glm-5.1': 15,
  'llama-4-maverick': 15, 'qwen-3-235b': 15, 'kira-2.5-pro': 10,
};

// ===== Full Security Check =====
async function securityCheck(req, version) {
  const result = { ok: false, error: '', status: 200 };

  // 1. API Key
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) { auditLog('API_KEY_MISSING', { ip: getClientIp(req) }); result.error = 'Missing API key'; result.status = 401; return result; }

  const keyData = await verifyApiKey(apiKey);
  if (!keyData) { const ip = getClientIp(req); recordIpFailure(ip); auditLog('API_KEY_INVALID', { ip }); result.error = 'Invalid API key'; result.status = 401; return result; }

  // 2. IP blacklist
  const clientIp = getClientIp(req);
  if (isIpBlacklisted(clientIp)) { result.error = 'IP temporarily blocked'; result.status = 429; return result; }

  // 3. Device
  const deviceId = req.headers['x-device-id'];
  const platform = req.headers['x-platform'];
  const versionHeader = req.headers['x-version'];
  if (!deviceId || !platform || !versionHeader) { result.error = 'Missing device info'; result.status = 401; return result; }
  if (!isDeviceAllowed(deviceId)) { auditLog('DEVICE_NOT_ALLOWED', { deviceId, ip: clientIp }); result.error = 'Device not registered'; result.status = 403; return result; }

  // 4. User identity
  const userEmail = keyData.email;
  const userProvider = keyData.provider || 'unknown';
  const userTier = keyData.tier || 'free';

  // 5. Session token (v2+ mandatory)
  const sessionToken = req.headers['x-session-token'];
  const bindingSig = req.headers['x-binding-signature'];
  const bindingTimestamp = req.headers['x-binding-timestamp'];
  const loginIp = req.headers['x-login-ip'];

  if (version >= 2) {
    if (!sessionToken) {
      if (!bindingSig || !bindingTimestamp || !loginIp) {
        auditLog('BINDING_MISSING', { deviceId, userEmail, version, ip: clientIp });
        result.error = 'Authentication required. Please login.'; result.status = 403; return result;
      }
      const validBinding = verifyBindingSignature(bindingSig, deviceId, userEmail, userProvider, loginIp, bindingTimestamp);
      if (!validBinding) { result.error = 'Invalid binding signature'; result.status = 403; return result; }
    } else {
      const tokenCheck = verifySessionToken(sessionToken, apiKey, deviceId, userEmail);
      if (!tokenCheck.valid) { result.error = tokenCheck.error; result.status = 403; return result; }
    }
  } else if (bindingSig && bindingTimestamp) {
    const validBinding = verifyBindingSignature(bindingSig, deviceId, userEmail, userProvider, loginIp || '', bindingTimestamp);
    if (!validBinding) { result.error = 'Invalid binding signature'; result.status = 403; return result; }
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

  // 8. HMAC signature (v1 optional for anonymous, v2+ mandatory)
  const timestamp = req.headers['x-timestamp'];
  const signature = req.headers['x-signature'];

  let bodyStr;
  try { bodyStr = canonicalJson(req.body); } catch { result.error = 'Invalid body'; result.status = 400; return result; }

  if (timestamp && signature) {
    if (!verifySignature(signature, timestamp, bodyStr, deviceId, apiKey)) {
      recordIpFailure(clientIp);
      result.error = 'Invalid signature'; result.status = 401; return result;
    }
  } else if (version >= 2) {
    result.error = 'Missing signature'; result.status = 401; return result;
  }

  // 9. Tier access
  if (!canAccessVersion(userTier, version)) {
    auditLog('TIER_BYPASS_ATTEMPT', { userEmail, userTier, requestedVersion: version });
    result.error = `Version v${version} requires ${getTierForVersion(version)} tier`; result.status = 403; return result;
  }

  // 10. Credit check
  const model = req.body.model || 'auto';
  const creditCost = MODEL_CREDIT_COST[model] || 1;
  const credits = await getCredits(apiKey);
  if (credits && credits.remaining < creditCost) {
    auditLog('CREDIT_EXCEEDED', { userEmail, model, creditCost, remaining: credits.remaining });
    result.error = `Insufficient credits. Need ${creditCost}, have ${credits.remaining}`; result.status = 429; return result;
  }

  // 11. Request validation
  const { messages } = req.body;
  if (!messages || !Array.isArray(messages) || messages.length === 0) { result.error = 'Messages required'; result.status = 400; return result; }
  if (bodyStr.length > 200000) { result.error = 'Request too large'; result.status = 413; return result; }

  // 12. Anomaly detection
  detectAnomalies(apiKey, clientIp, loginIp);

  clearIpFailure(clientIp);

  result.ok = true;
  result.apiKey = apiKey.substring(0, 10) + '...';
  result.userEmail = userEmail;
  result.userProvider = userProvider;
  result.userTier = userTier;
  result.clientIp = clientIp;
  result.loginIp = loginIp;
  result.bodyStr = bodyStr;
  result.creditCost = creditCost;
  return result;
}

function getAuditLog(limit = 100) { return state.auditLog.slice(-limit); }
function getSecurityStats() {
  return {
    rateLimitsActive: state.rateLimits.size,
    ipBlacklisted: state.ipBlacklist.size,
    sessionTokensActive: state.sessionTokens.size,
    auditLogEntries: state.auditLog.length,
    recentEvents: state.auditLog.slice(-10),
  };
}

module.exports = {
  GATEWAY_SECRET, MAX_AGE_MS, SESSION_TOKEN_TTL_MS,
  hmacSign, deriveUserSecret, generateSessionToken, verifySessionToken,
  verifySignature, canonicalJson, isDeviceAllowed, checkRateLimit,
  canAccessVersion, getTierForVersion, securityCheck, getClientIp,
  verifyBindingSignature, TIER_ORDER, isIpBlacklisted, recordIpFailure,
  getAuditLog, getSecurityStats, MODEL_CREDIT_COST,
};
