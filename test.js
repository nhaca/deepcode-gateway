const crypto = require('crypto');
const https = require('https');

const GATEWAY_KEY = 'deepcode-gw-key-2024';
const GATEWAY_SECRET = 'dc-gw-secret-2024-secure';
const DEVICE_ID = 'deepcode-ide-v1';
const TEST_EMAIL = 'test@example.com';
const TEST_IP = '192.168.1.100';

function sign(body) {
  const timestamp = Date.now().toString();
  const message = `${timestamp}:${DEVICE_ID}:${body}`;
  const hmac = crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');
  return { timestamp, signature: hmac };
}

function headers(timestamp, signature, tier = 'free', extra = {}) {
  return {
    'Authorization': `Bearer ${GATEWAY_KEY}`,
    'Content-Type': 'application/json',
    'X-Timestamp': timestamp,
    'X-Signature': signature,
    'X-Device-ID': DEVICE_ID,
    'X-Platform': 'win32',
    'X-Version': '1.0.0',
    'X-User-Email': TEST_EMAIL,
    'X-User-Provider': 'google',
    'X-User-Tier': tier,
    ...extra,
  };
}

function req(path, body, hdrs) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const r = https.request({ hostname: 'deepcode-gateway.vercel.app', path, method: 'POST', headers: hdrs }, res => {
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
  // 1. Bind device
  console.log('=== 1. Bind Device ===');
  const bindBody = JSON.stringify({ action: 'bind', deviceId: DEVICE_ID, email: TEST_EMAIL, provider: 'google', ip: TEST_IP });
  const { timestamp: t1, signature: s1 } = sign(bindBody);
  const bindRes = await req('/bind-device', JSON.parse(bindBody), headers(t1, s1));
  console.log(`  Status: ${bindRes.status}, Body: ${bindRes.body}`);

  // 2. v1 (DeepCode Go) - free tier
  console.log('\n=== 2. v1 DeepCode Go (free) ===');
  const v1Body = JSON.stringify({ model: 'auto', messages: [{ role: 'user', content: 'say hi in 5 words' }], max_tokens: 20 });
  const { timestamp: t2, signature: s2 } = sign(v1Body);
  const v1Res = await req('/v1/chat/completions', JSON.parse(v1Body), headers(t2, s2, 'free'));
  console.log(`  Status: ${v1Res.status}, Body: ${v1Res.body}`);

  // 3. v2 (DeepCode Pro) - free tier → should fail
  console.log('\n=== 3. v2 DeepCode Pro (free tier → should fail) ===');
  const v2Body = JSON.stringify({ model: 'z-ai/glm-4.7-flash-free', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 });
  const { timestamp: t3, signature: s3 } = sign(v2Body);
  const v2ResFree = await req('/v2/chat/completions', JSON.parse(v2Body), headers(t3, s3, 'free'));
  console.log(`  Status: ${v2ResFree.status}, Body: ${v2ResFree.body}`);

  // 4. v2 (DeepCode Pro) - pro tier
  console.log('\n=== 4. v2 DeepCode Pro (pro tier) ===');
  const { timestamp: t4, signature: s4 } = sign(v2Body);
  const v2ResPro = await req('/v2/chat/completions', JSON.parse(v2Body), headers(t4, s4, 'pro'));
  console.log(`  Status: ${v2ResPro.status}, Body: ${v2ResPro.body}`);

  // 5. v4 (DeepCode Server 2) - free tier → should fail
  console.log('\n=== 5. v4 DeepCode Server 2 (free tier → should fail) ===');
  const v4Body = JSON.stringify({ model: 'auto', messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 });
  const { timestamp: t5, signature: s5 } = sign(v4Body);
  const v4ResFree = await req('/v4/chat/completions', JSON.parse(v4Body), headers(t5, s5, 'free'));
  console.log(`  Status: ${v4ResFree.status}, Body: ${v4ResFree.body}`);

  // 6. v4 (DeepCode Server 2) - pro tier
  console.log('\n=== 6. v4 DeepCode Server 2 (pro tier) ===');
  const { timestamp: t6, signature: s6 } = sign(v4Body);
  const v4ResPro = await req('/v4/chat/completions', JSON.parse(v4Body), headers(t6, s6, 'pro'));
  console.log(`  Status: ${v4ResPro.status}, Body: ${v4ResPro.body}`);

  // 7. v4 with specific model (claude-opus-4-8) - pro tier
  console.log('\n=== 7. v4/claude-opus-4-8 (pro tier) ===');
  const claudeBody = JSON.stringify({ messages: [{ role: 'user', content: 'hi' }], max_tokens: 10 });
  const { timestamp: t7, signature: s7 } = sign(claudeBody);
  const claudeRes = await req('/v4/chat/completions/claude-opus-4-8', JSON.parse(claudeBody), headers(t7, s7, 'pro'));
  console.log(`  Status: ${claudeRes.status}, Body: ${claudeRes.body}`);

  // 8. Wrong IP → should fail
  console.log('\n=== 8. Wrong IP (should fail) ===');
  const { timestamp: t8, signature: s8 } = sign(v1Body);
  const wrongIpRes = await req('/v1/chat/completions', JSON.parse(v1Body), { ...headers(t8, s8, 'free'), 'X-Forwarded-For': '10.0.0.1' });
  console.log(`  Status: ${wrongIpRes.status}, Body: ${wrongIpRes.body}`);

  console.log('\n=== Done ===');
}

test().catch(console.error);
