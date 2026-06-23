const crypto = require('crypto');

const GATEWAY_KEY = process.env.GATEWAY_KEY || 'deepcode-gw-key-2024';
const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dc-gw-secret-2024-secure';
const MAX_AGE_MS = 15000;

// ===== Device Binding =====
// 1 device = 1 user (email). Multiple accounts on same device → merge usage.
const deviceBindings = new Map(); // deviceId → { email, provider, loginIp, loginTime, linkedAccounts: [{email, provider}] }

function bindDevice(deviceId, email, provider, loginIp) {
  const existing = deviceBindings.get(deviceId);
  if (existing) {
    // Device already bound — check if same user
    if (existing.email === email) {
      // Same user, just update login time
      existing.loginTime = Date.now();
      existing.loginIp = loginIp;
      return { success: true, merged: false };
    }
    // Different user on same device → merge usage
    const alreadyLinked = existing.linkedAccounts.some(a => a.email === email);
    if (!alreadyLinked) {
      existing.linkedAccounts.push({ email, provider, addedAt: Date.now() });
    }
    existing.loginTime = Date.now();
    existing.loginIp = loginIp;
    return { success: true, merged: true, primaryEmail: existing.email };
  }
  // New device binding
  deviceBindings.set(deviceId, {
    email,
    provider,
    loginIp,
    loginTime: Date.now(),
    linkedAccounts: [],
  });
  return { success: true, merged: false };
}

function verifyDeviceBinding(deviceId, email) {
  const binding = deviceBindings.get(deviceId);
  if (!binding) return { valid: false, error: 'Device not bound' };
  // Check if email is primary or linked
  if (binding.email === email) return { valid: true, merged: false };
  const isLinked = binding.linkedAccounts.some(a => a.email === email);
  if (isLinked) return { valid: true, merged: true, primaryEmail: binding.email };
  return { valid: false, error: 'Email not linked to this device' };
}

function getDeviceBinding(deviceId) {
  return deviceBindings.get(deviceId) || null;
}

// ===== IP Consistency =====
// Compare IP at login vs IP at API call
function verifyIpConsistency(deviceId, currentIp) {
  const binding = deviceBindings.get(deviceId);
  if (!binding) return { valid: false, error: 'Device not bound' };
  if (!binding.loginIp || !currentIp) return { valid: true }; // Skip if IP unknown
  // Allow same /24 subnet (e.g., 192.168.1.x)
  const loginSubnet = binding.loginIp.split('.').slice(0, 3).join('.');
  const currentSubnet = currentIp.split('.').slice(0, 3).join('.');
  if (binding.loginIp === currentIp) return { valid: true };
  if (loginSubnet === currentSubnet) return { valid: true, warning: 'IP changed but same subnet' };
  return { valid: false, error: 'IP address changed significantly. Please re-login.' };
}

function getClientIp(req) {
  // Vercel / Vercel serverless: x-forwarded-for
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    return first.split(',')[0].trim();
  }
  // Direct connection
  return req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

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

// ===== Device Whitelist =====
const ALLOWED_DEVICES = new Set(['deepcode-ide-v1']);

function isDeviceAllowed(deviceId) {
  return ALLOWED_DEVICES.has(deviceId);
}

// ===== Rate Limiter =====
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
  free: 1,   // v1 only
  pro: 2,    // v1, v2
  premium: 3, // v1, v2, v3
  business: 4, // v1, v2, v3, v4
  ultra: 4,  // v1, v2, v3, v4
};

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

  // 3. User identity
  const userEmail = req.headers['x-user-email'];
  const userProvider = req.headers['x-user-provider'];
  if (!userEmail) {
    result.error = 'Missing user identity'; result.status = 401; return result;
  }

  // 4. Device binding — this email must be bound to this device
  const bindingCheck = verifyDeviceBinding(deviceId, userEmail);
  if (!bindingCheck.valid) {
    result.error = bindingCheck.error; result.status = 403; return result;
  }

  // 5. IP consistency
  const clientIp = getClientIp(req);
  const ipCheck = verifyIpConsistency(deviceId, clientIp);
  if (!ipCheck.valid) {
    result.error = ipCheck.error; result.status = 403; return result;
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
  try { bodyStr = JSON.stringify(req.body); } catch {
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
  result.bindingCheck = bindingCheck;
  result.bodyStr = bodyStr;
  return result;
}

module.exports = {
  GATEWAY_KEY,
  GATEWAY_SECRET,
  MAX_AGE_MS,
  bindDevice,
  verifyDeviceBinding,
  getDeviceBinding,
  verifyIpConsistency,
  getClientIp,
  hmacSign,
  verifySignature,
  isDeviceAllowed,
  checkRateLimit,
  canAccessVersion,
  getTierForVersion,
  securityCheck,
  deviceBindings,
};
