const crypto = require('crypto');
const https = require('https');

const GATEWAY_KEY = 'deepcode-gw-key-2024';
const GATEWAY_SECRET = 'dc-gw-secret-2024-secure';
const DEVICE_ID = 'deepcode-ide-v1';

const body = JSON.stringify({model:'auto',messages:[{role:'user',content:'hi'}],max_tokens:10});
const timestamp = Date.now().toString();
const message = timestamp + ':' + DEVICE_ID + ':' + body;
const signature = crypto.createHmac('sha256', GATEWAY_SECRET).update(message).digest('hex');

console.log('Timestamp:', timestamp);
console.log('Signature:', signature.substring(0, 30) + '...');

const req = https.request({
  hostname: 'deepcode-gateway.vercel.app',
  path: '/v1/chat/completions',
  method: 'POST',
  headers: {
    'Authorization': 'Bearer ' + GATEWAY_KEY,
    'Content-Type': 'application/json',
    'X-Timestamp': timestamp,
    'X-Signature': signature,
    'X-Device-ID': DEVICE_ID,
    'X-Platform': 'win32',
    'X-Version': '1.0.0',
    'Content-Length': Buffer.byteLength(body)
  }
}, res => {
  console.log('Status:', res.statusCode);
  let data = '';
  res.on('data', chunk => { data += chunk; });
  res.on('end', () => { console.log('Response:', data.substring(0, 200)); });
});
req.write(body);
req.end();
