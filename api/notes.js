import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

let verifyLogin;

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }

  try {
    verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: key });
  } catch {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }

  // 신원은 검증된 토큰에서만 얻는다. 요청에 실려 온 userId·role은 읽지 않는다.
  const login = await verifyLogin(request.headers.authorization);
  if (!login) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    return response.status(401).json({ error: 'LOGIN_REQUIRED' });
  }

  let supabase;
  try {
    supabase = createClient(url, key, { auth: { persistSession: false } });
  } catch {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }

  const { data, error } = await supabase
    .from('notes')
    .select('title, content');

  if (error) {
    return response.status(502).json({ error: 'NOTES_FETCH_FAILED' });
  }

  response.status(200).json({ notes: data });
}
