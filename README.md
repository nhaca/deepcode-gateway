# DeepCode Gateway

AI Gateway ẩn tất cả API keys, chạy trên Vercel.

## Deploy

1. Push repo lên GitHub
2. Import vào Vercel
3. Thêm Environment Variables:

```
GATEWAY_SECRET = your_64_char_random_secret
GOOGLE_KEYS = AIzaSy...
GROQ_KEYS = gsk_...
NVIDIA_KEYS = nvapi-...
OPENROUTER_KEYS = sk-or-...
```

4. Deploy

## Usage

```
POST https://deepcode.vercel.app/v1/chat/completions
Authorization: Bearer your_gateway_secret
Content-Type: application/json

{
  "model": "auto",
  "messages": [{"role": "user", "content": "hello"}],
  "stream": false
}
```

## IDE Integration

Trong main.js, thay vì gọi trực tiếp providers:

```javascript
const GATEWAY_URL = 'https://deepcode.vercel.app';
const GATEWAY_KEY = process.env.GATEWAY_SECRET;

// Thay vì gọi zenmux/cloudflare/nvidia trực tiếp
const res = await fetch(`${GATEWAY_URL}/v1/chat/completions`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${GATEWAY_KEY}`,
  },
  body: JSON.stringify({ model, messages, stream }),
});
```

User chỉ thấy `deepcode.vercel.app` - không biết providers nào ở sau.
