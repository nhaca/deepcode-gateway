const GATEWAY_KEY = process.env.GATEWAY_KEY || 'deepcode-gw-key-2024';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const auth = req.headers.authorization;
  if (!auth || auth !== `Bearer ${GATEWAY_KEY}`) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const models = [
    { id: 'auto', name: 'Auto (Best Available)' },
    { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash (Google)' },
    { id: 'llama-3.3-70b-versatile', name: 'Llama 3.3 70B (Groq)' },
    { id: 'deepseek-ai/deepseek-v4-flash', name: 'DeepSeek V4 Flash (NVIDIA)' },
    { id: 'z-ai/glm-5.1', name: 'GLM 5.1 (NVIDIA)' },
    { id: 'nvidia/nemotron-3-super-120b-a12b', name: 'Nemotron 3 Super 120B (NVIDIA)' },
  ];

  return res.json({ object: 'list', data: models.map(m => ({ ...m, object: 'model', owned_by: 'deepcode-gateway' })) });
}
