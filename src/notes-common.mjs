import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { protectedAccess } from './protected-access.mjs';
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
    console.warn(JSON.stringify({ event: 'login_rejected', ...loginFailureHint(request.headers.authorization) }));
    response.setHeader('WWW-Authenticate', 'Bearer');
    fail(response, 401, 'LOGIN_REQUIRED');
    return null;
  }

  // 로그인만으로는 보호 자료를 열지 않는다. 서버가 이 기기의 승인을 확인해야 한다(어댑터가 없으면 503).
  const gate = await protectedAccess.check(login);
  if (!gate.ok) {
    console.warn(JSON.stringify({ event: 'device_gate', error: gate.error }));
    fail(response, gate.status, gate.error);
    return null;
  }
  return { userId: login.userId.toLowerCase(), db: database, kind: login.kind };
}

// 로그인 거부 사유 분류만 남긴다. 토큰 원문·서명·사용자 ID(sub)는 남기지 않는다.
function loginFailureHint(authorization) {
  if (typeof authorization !== 'string' || !authorization) return { reason: 'no_authorization' };
  const parts = /^Bearer ([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]+$/u.exec(authorization);
  if (!parts) return { reason: 'not_bearer_jwt' };
  try {
    const head = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[2], 'base64url').toString('utf8'));
    const issuer = claims.iss === config.judgeIssuer ? 'judge'
      : claims.iss === config.identityProvider?.issuer ? 'student' : 'unknown';
    const hint = { reason: 'verify_failed', issuer, alg: head.alg };
    if (issuer === 'unknown' && typeof claims.iss === 'string') {
      try { hint.issuerHost = new URL(claims.iss).host; } catch { hint.issuerHost = 'unparsable'; }
    }
    if (issuer === 'judge') {
      Object.assign(hint, { aud: claims.aud, expectedAud: new URL(config.publicAppUrl).hostname,
        role: claims.aleph_role, identity: claims.aleph_identity, ttl: claims.exp - claims.iat });
    }
    return hint;
  } catch {
    return { reason: 'unreadable_jwt' };
  }
}

// 거부할 때는 자원 ID 와 짧은 사유만 로그에 남긴다. 토큰·사용자 ID·메모 본문은 남기지 않는다.
export function forbid(response, resource, reason) {
  console.warn(JSON.stringify({ event: 'access_denied', resource, reason }));
  return response.status(403).json({ error: 'FORBIDDEN', reason });
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
