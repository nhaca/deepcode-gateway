const crypto = require('crypto');

const GATEWAY_SECRET = process.env.GATEWAY_SECRET || 'dc-gw-secret-2024-secure';
const GATEWAY_KEY = process.env.GATEWAY_KEY || 'deepcode-gw-key-2024';
const MAX_AGE_MS = 30000; // 30 seconds

function verifySignature(signature, timestamp, body) {
  const age = Date.now() - parseInt(timestamp);
  if (isNaN(age) || age < 0 || age > MAX_AGE_MS) return false;

  const message = `${timestamp}:${body}`;
  const expected = crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function generateSignature(timestamp, body) {
  const message = `${timestamp}:${body}`;
  return crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');
}

module.exports = { verifySignature, generateSignature, GATEWAY_KEY };
