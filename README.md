# DeepCode Gateway

AI Gateway ẩn tất cả API keys, chạy trên Vercel.

## Deploy

1. Push repo lên GitHub
2. Import vào Vercel
3. Thêm Environment Variables:

```
GATEWAY_KEY = deepcode-gw-key-2024
GOOGLE_KEYS = AIzaSy...1,AIzaSy...2,AIzaSy...3
GROQ_KEYS = gsk_...1,gsk_...2,gsk_...3
NVIDIA_KEYS = nvapi-...1,nvapi-...2,nvapi-...3
OPENROUTER_KEYS = sk-or-...1,sk-or-...2
```

4. Deploy

## Usage

```
POST https://deepcode.vercel.app/v1/chat/completions
Authorization: Bearer deepcode-gw-key-2024
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
const GATEWAY_KEY = 'deepcode-gw-key-2024';

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
