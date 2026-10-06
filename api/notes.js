import { createClient } from '@supabase/supabase-js';

export default async function handler(_request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;

  if (!url || !key) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
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
