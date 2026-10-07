import { authSettings, callAuth, publicSession } from '../../src/auth-proxy.mjs';
import { fail, readJsonObject } from '../../src/notes-common.mjs';

const BEARER = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;

function reply(response, status, error, message) {
  return response.status(status).json({ error, message });
}

function unavailable(response) {
  return reply(response, 502, 'AUTH_UNAVAILABLE', '로그인 서버에 연결하지 못했습니다. 잠시 뒤 다시 시도해 주세요.');
}

// Supabase가 준 세션이 올바른 모양일 때만 로그인된 것으로 본다.
function sendSession(response, { json }) {
  if (typeof json?.access_token !== 'string' || typeof json?.refresh_token !== 'string'
      || typeof json?.user?.id !== 'string') {
    return unavailable(response);
  }
  return response.status(200).json(publicSession(json));
}

function authFailure(response, result, error, message) {
  if (result.status === 0 || result.status >= 500) return unavailable(response);
  if (result.status === 429) {
    return reply(response, 429, 'RATE_LIMITED', '시도가 너무 많습니다. 잠시 뒤 다시 시도해 주세요.');
  }
  // 공개 키 자체를 거부하면(오류 코드 없는 401·403) 비밀번호 문제가 아니라 서버 설정 문제다.
  if ((result.status === 401 || result.status === 403) && !result.json?.error_code) {
    return reply(response, 503, 'AUTH_MISCONFIGURED', '로그인 서버 설정에 문제가 있습니다. 관리자에게 알려 주세요.');
  }
  return reply(response, 401, error, message);
}

const actions = {
  async login(request, response, settings) {
    const { email, password } = readJsonObject(request) ?? {};
    if (typeof email !== 'string' || typeof password !== 'string'
        || !email.trim() || !password || email.length > 254 || password.length > 1000) {
      return reply(response, 400, 'INVALID_LOGIN', '이메일과 비밀번호를 입력해 주세요.');
    }
    const result = await callAuth(settings, '/token?grant_type=password',
      { body: { email: email.trim(), password } });
    if (result.status === 200) return sendSession(response, result);
    const code = result.json?.error_code ?? result.json?.error;
    const message = code === 'email_not_confirmed'
      ? '이메일 인증이 아직 안 된 계정입니다.'
      : '이메일 또는 비밀번호가 맞지 않습니다.';
    return authFailure(response, result, 'LOGIN_FAILED', message);
  },

  async refresh(request, response, settings) {
    const token = readJsonObject(request)?.refresh_token;
    if (typeof token !== 'string' || !token || token.length > 500) {
      return reply(response, 400, 'INVALID_REFRESH', '다시 로그인해 주세요.');
    }
    const result = await callAuth(settings, '/token?grant_type=refresh_token',
      { body: { refresh_token: token } });
    if (result.status === 200) return sendSession(response, result);
    return authFailure(response, result, 'SESSION_EXPIRED', '로그인이 만료되었습니다. 다시 로그인해 주세요.');
  },

  async logout(request, response, settings) {
    const bearer = BEARER.exec(request.headers.authorization ?? '')?.[1];
    if (!bearer) return fail(response, 401, 'LOGIN_REQUIRED');
    const result = await callAuth(settings, '/logout?scope=local', { bearer });
    if (result.status === 0 || result.status >= 500) return unavailable(response);
    return response.status(204).end();
  },
};

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  const action = Object.hasOwn(actions, request.query?.action) ? actions[request.query.action] : null;
  if (!action) return fail(response, 404, 'NOT_FOUND');
  const settings = authSettings();
  if (!settings) {
    return reply(response, 503, 'AUTH_UNAVAILABLE', '로그인 기능이 아직 설정되지 않았습니다.');
  }
  return action(request, response, settings);
}
