const crypto = require('crypto');
const https = require('https');

const GATEWAY_KEY = 'deepcode-gw-key-2024';
const GATEWAY_SECRET = 'dc-gw-secret-2024-secure';
const DEVICE_ID = 'deepcode-ide-v1';
const TEST_EMAIL = 'test@example.com';

function canonicalJson(obj) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

function sign(body) {
  const timestamp = Date.now().toString();
  const bodyStr = typeof body === 'string' ? body : canonicalJson(body);
  const message = `${timestamp}:${DEVICE_ID}:${bodyStr}`;
  const hmac = crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');
  return { timestamp, signature: hmac };
}

function bindingSignature(email, provider, ip, timestamp) {
  const message = `${DEVICE_ID}:${email}:${provider}:${ip}:${timestamp}`;
  return crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');
}

function req(path, body, hdrs) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const h = { ...hdrs, 'Content-Length': Buffer.byteLength(data) };
    const r = https.request({ hostname: 'deepcode-gateway.vercel.app', path, method: 'POST', headers: h }, res => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 300) }));
    });
    r.on('error', reject);
    r.write(data);
    r.end();
  });
}

function getPublicIP() {
  return new Promise((resolve) => {
    https.get('https://api.ipify.org?format=json', res => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => { try { resolve(JSON.parse(d).ip); } catch { resolve('unknown'); } });
    }).on('error', () => resolve('unknown'));
  });
}

async function test() {
  const realIp = await getPublicIP();
  console.log('Real IP:', realIp);

  const bindingTs = Date.now().toString();
  const bindSig = bindingSignature(TEST_EMAIL, 'google', realIp, bindingTs);

  function headers(tier = 'free', extra = {}) {
    return {
      'Authorization': `Bearer ${GATEWAY_KEY}`,
      'Content-Type': 'application/json',
      'X-Device-ID': DEVICE_ID,
      'X-Platform': 'win32',
      'X-Version': '1.0.0',
      'X-User-Email': TEST_EMAIL,
      'X-User-Provider': 'google',
      'X-User-Tier': tier,
      'X-Binding-Signature': bindSig,
      'X-Binding-Timestamp': bindingTs,
      'X-Login-IP': realIp,
      ...extra,
    };
  }

  // 1. v1 DeepCode Go (free)
  console.log('\n=== 1. v1 DeepCode Go (free) ===');
  const v1Body = { model: 'auto', messages: [{ role: 'user', content: 'say hi in 3 words' }], max_tokens: 20 };
  const { timestamp: t1, signature: s1 } = sign(JSON.stringify(v1Body));
  const v1 = await req('/v1/chat/completions', v1Body, { ...headers('free'), 'X-Timestamp': t1, 'X-Signature': s1 });
  console.log(`  ${v1.status}: ${v1.body}`);

  // 2. v2 DeepCode Pro (free → should fail)
  console.log('\n=== 2. v2 DeepCode Pro (free → 403) ===');
  const v2Body = { model: 'z-ai/glm-4.7-flash-free', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 };
  const { timestamp: t2, signature: s2 } = sign(JSON.stringify(v2Body));
  const v2f = await req('/v2/chat/completions', v2Body, { ...headers('free'), 'X-Timestamp': t2, 'X-Signature': s2 });
  console.log(`  ${v2f.status}: ${v2f.body}`);

  // 3. v2 DeepCode Pro (pro)
  console.log('\n=== 3. v2 DeepCode Pro (pro) ===');
  const { timestamp: t3, signature: s3 } = sign(JSON.stringify(v2Body));
  const v2p = await req('/v2/chat/completions', v2Body, { ...headers('pro'), 'X-Timestamp': t3, 'X-Signature': s3 });
  console.log(`  ${v2p.status}: ${v2p.body}`);

  // 4. v3 DeepCode Ultra (pro)
  console.log('\n=== 4. v3 DeepCode Ultra (pro) ===');
  const v3Body = { model: 'z-ai/glm-5.1', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 };
  const { timestamp: t4, signature: s4 } = sign(JSON.stringify(v3Body));
  const v3 = await req('/v3/chat/completions', v3Body, { ...headers('pro'), 'X-Timestamp': t4, 'X-Signature': s4 });
  console.log(`  ${v3.status}: ${v3.body}`);

  // 5. v4 DeepCode Server 2 (pro)
  console.log('\n=== 5. v4 DeepCode Server 2 (pro) ===');
  const v4Body = { model: 'auto', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 };
  const { timestamp: t5, signature: s5 } = sign(JSON.stringify(v4Body));
  const v4 = await req('/v4/chat/completions', v4Body, { ...headers('pro'), 'X-Timestamp': t5, 'X-Signature': s5 });
  console.log(`  ${v4.status}: ${v4.body}`);

  // 6. v4/claude-opus-4-8 (pro)
  console.log('\n=== 6. v4/claude-opus-4-8 (pro) ===');
  const claudeBody = { messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 };
  const { timestamp: t6, signature: s6 } = sign(JSON.stringify(claudeBody));
  const claude = await req('/v4/chat/completions/claude-opus-4-8', claudeBody, { ...headers('pro'), 'X-Timestamp': t6, 'X-Signature': s6 });
  console.log(`  ${claude.status}: ${claude.body}`);

  // 7. Wrong IP
  console.log('\n=== 7. Wrong IP (should fail) ===');
  const { timestamp: t7, signature: s7 } = sign(JSON.stringify(v1Body));
  const wrongIp = await req('/v1/chat/completions', v1Body, { ...headers('free'), 'X-Timestamp': t7, 'X-Signature': s7, 'X-Forwarded-For': '10.0.0.1' });
  console.log(`  ${wrongIp.status}: ${wrongIp.body}`);

  console.log('\n=== Done ===');
}

test().catch(console.error);
