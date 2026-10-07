import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TITLE_MAX = 200;
const BODY_MAX = 5000;

export const NOTE_COLUMNS = 'id, title, content';

let verifyLogin;
let database;

export function fail(response, status, error) {
  return response.status(status).json({ error });
}

// 로그인한 사용자 ID와 DB 연결을 돌려준다. 거부할 때는 응답을 이미 보내고 null을 돌려준다.
export async function authenticate(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) {
    fail(response, 503, 'NOTES_UNAVAILABLE');
    return null;
  }

  try {
    verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: key });
    database ??= createClient(url, key, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
  } catch {
    fail(response, 503, 'NOTES_UNAVAILABLE');
    return null;
  }

  // 신원은 검증된 토큰에서만 얻는다. 요청에 실려 온 userId·role·owner_id는 읽지 않는다.
  const login = await verifyLogin(request.headers.authorization);
  if (!login) {
    response.setHeader('WWW-Authenticate', 'Bearer');
    fail(response, 401, 'LOGIN_REQUIRED');
    return null;
  }
  return { userId: login.userId, db: database };
}

export function parseId(value) {
  return typeof value === 'string' && UUID.test(value) ? value.toLowerCase() : null;
}

export function readJsonObject(request) {
  let body;
  try {
    body = request.body;
  } catch {
    return null;
  }
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch {
      return null;
    }
  }
  return body !== null && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

const isText = (value, max, allowBlank) =>
  typeof value === 'string' && value.length <= max && (allowBlank || value.trim() !== '');

// 제목·내용을 검사해 DB 칸 이름(title, content)으로 돌려준다. 잘못되면 null.
export function readNoteFields(input, { requireTitle }) {
  const fields = {};
  if (input.title !== undefined) {
    if (!isText(input.title, TITLE_MAX, false)) return null;
    fields.title = input.title;
  } else if (requireTitle) {
    return null;
  }
  if (input.body !== undefined) {
    if (!isText(input.body, BODY_MAX, true)) return null;
    fields.content = input.body;
  }
  return fields;
}

export const toNote = ({ id, title, content }) => ({ id, title, body: content });
