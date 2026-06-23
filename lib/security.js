const crypto = require('crypto');

const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dc-gw-secret-2024-secure';
const MAX_AGE_MS = 15000; // 15 seconds (giảm từ 30s)

// Device whitelist - chỉ cho phép các device đã register
const ALLOWED_DEVICES = new Set([
  'deepcode-ide-v1', // Default device ID
]);

function getDeviceFingerprint(req) {
  const hwid = req.headers.get('x-device-id');
  const platform = req.headers.get('x-platform');
  const version = req.headers.get('x-version');
  return `${hwid}:${platform}:${version}`;
}

function verifyDevice(deviceId) {
  return ALLOWED_DEVICES.has(deviceId);
}

async function hmacSign(secret, message) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
  return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifySignature(signature, timestamp, bodyStr, deviceId) {
  // 1. Check timestamp
  const age = Date.now() - parseInt(timestamp);
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) return false;

  // 2. Check device
  if (!verifyDevice(deviceId)) return false;

  // 3. Verify HMAC
  const message = `${timestamp}:${deviceId}:${bodyStr}`;
  const expected = await hmacSign(GATEWAY_SECRET, message);
  return signature === expected;
}

// Simple in-memory rate limiter
const rateLimits = new Map();
function checkRateLimit(deviceId, maxRequests = 50, windowMs = 60000) {
  const now = Date.now();
  const record = rateLimits.get(deviceId) || { count: 0, resetAt: now + windowMs };
  
  if (now > record.resetAt) {
    record.count = 0;
    record.resetAt = now + windowMs;
  }
  
  record.count++;
  rateLimits.set(deviceId, record);
  
  return record.count <= maxRequests;
}

module.exports = { 
  verifySignature, 
  hmacSign, 
  getDeviceFingerprint, 
  verifyDevice, 
  checkRateLimit,
  ALLOWED_DEVICES,
  MAX_AGE_MS 
};
