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

function getPublicIP() {
  return new Promise((resolve) => {
    https.get('https://api.ipify.org?format=json', res => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => { try { resolve(JSON.parse(d).ip); } catch { resolve('unknown'); } });
    }).on('error', () => resolve('unknown'));
  });
}

function sign(body, timestamp) {
  const canonical = canonicalJson(body);
  const message = `${timestamp}:${DEVICE_ID}:${canonical}`;
  return crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');
}

function req(path, body, hdrs) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const h = { ...hdrs, 'Content-Length': Buffer.byteLength(data) };
    const r = https.request({ hostname: 'deepcode-gateway.vercel.app', path, method: 'POST', headers: h }, res => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 200) }));
    });
    r.on('error', reject);
    r.write(data);
    r.end();
  });
}

async function test() {
  const realIp = await getPublicIP();
  console.log('Real IP:', realIp);

  const bindingTs = Date.now().toString();
  const bindSig = crypto.createHmac('sha256', GATEWAY_SECRET).update(`${DEVICE_ID}:${TEST_EMAIL}:google:${realIp}:${bindingTs}`).digest('hex');

  function hdrs(tier = 'free') {
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
    };
  }

  function makeReq(path, body, tier = 'free') {
    const timestamp = Date.now().toString();
    const sig = sign(body, timestamp);
    return req(path, body, { ...hdrs(tier), 'X-Timestamp': timestamp, 'X-Signature': sig });
  }

  // 1. v1 (Go, free)
  console.log('\n=== 1. v1 DeepCode Go (free) ===');
  let r = await makeReq('/v1/chat/completions', { model: 'auto', messages: [{ role: 'user', content: 'say hi in 3 words' }], max_tokens: 20 });
  console.log(`  ${r.status}: ${r.body}`);

  // 2. v2 (Pro, free → 403)
  console.log('\n=== 2. v2 DeepCode Pro (free → 403) ===');
  r = await makeReq('/v2/chat/completions', { model: 'z-ai/glm-4.7-flash-free', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 });
  console.log(`  ${r.status}: ${r.body}`);

  // 3. v2 (Pro, pro tier)
  console.log('\n=== 3. v2 DeepCode Pro (pro tier) ===');
  r = await makeReq('/v2/chat/completions', { model: 'z-ai/glm-4.7-flash-free', messages: [{ role: 'user', content: 'say hi in 3 words' }], max_tokens: 20 }, 'pro');
  console.log(`  ${r.status}: ${r.body}`);

  // 4. v3 (Ultra, pro)
  console.log('\n=== 4. v3 DeepCode Ultra (pro) ===');
  r = await makeReq('/v3/chat/completions', { model: 'z-ai/glm-5.1', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 }, 'pro');
  console.log(`  ${r.status}: ${r.body}`);

  // 5. v4 (Server 2, pro)
  console.log('\n=== 5. v4 DeepCode Server 2 (pro) ===');
  r = await makeReq('/v4/chat/completions', { model: 'auto', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 }, 'pro');
  console.log(`  ${r.status}: ${r.body}`);

  // 6. v4/claude-opus-4-8 (pro)
  console.log('\n=== 6. v4/claude-opus-4-8 (pro) ===');
  r = await makeReq('/v4/chat/completions/claude-opus-4-8', { messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 }, 'pro');
  console.log(`  ${r.status}: ${r.body}`);

  // 7. Wrong IP
  console.log('\n=== 7. Wrong IP (should fail) ===');
  const timestamp = Date.now().toString();
  const sig = sign({ model: 'auto', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 }, timestamp);
  r = await req('/v1/chat/completions', { model: 'auto', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 }, {
    ...hdrs('free'), 'X-Timestamp': timestamp, 'X-Signature': sig, 'X-Forwarded-For': '10.0.0.1'
  });
  console.log(`  ${r.status}: ${r.body}`);

  console.log('\n=== Done ===');
}

test().catch(console.error);
