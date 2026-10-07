import crypto from 'node:crypto';

// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 3) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  const issuer = config.identityProvider?.issuer;
  if (typeof issuer !== 'string') throw new Error('aleph.config.json의 identityProvider를 먼저 채워 주세요.');

  // 없는 id로 보내서, 보호가 풀려 있어도 실제 메모가 바뀌지 않게 한다. POST도 빈 본문이라 저장되지 않는다.
  const missingId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);

  const data = await send(app, 'GET', '/data.json');
  const listNoToken = await send(app, 'GET', '/api/notes');
  const createNoToken = await send(app, 'POST', '/api/notes', { body: {} });
  const itemGet = await send(app, 'GET', `/api/notes/${missingId}`);
  const itemPut = await send(app, 'PUT', `/api/notes/${missingId}`, { body: { title: '점검' } });
  const itemDelete = await send(app, 'DELETE', `/api/notes/${missingId}`);
  const forged = await send(app, 'GET', '/api/notes', { token: forgedToken(issuer, {}) });
  const expired = await send(app, 'GET', '/api/notes',
    { token: forgedToken(issuer, { iat: now - 7200, exp: now - 3600 }) });
  const otherService = await send(app, 'GET', '/api/notes',
    { token: forgedToken(issuer, { aud: 'other-service' }) });

  const exposed = (Array.isArray(data.json?.notes) && data.json.notes.length > 0)
    || (typeof config.sampleMarker === 'string' && data.text.includes(config.sampleMarker));
  const items = [itemGet, itemPut, itemDelete];
  const itemStatuses = `GET ${itemGet.status} · PUT ${itemPut.status} · DELETE ${itemDelete.status}`;

  return [
    {
      attackId: 'data_json_notes_empty',
      expected: '/data.json에 가상 메모와 확인 표시가 없어야 함',
      observed: failedToSend(data)
        ? `요청 실패(${data.status}) — 확인 못 함`
        : exposed
          ? `/data.json에 메모 또는 확인 표시가 남아 있음 (HTTP ${data.status})`
          : `/data.json에 메모·확인 표시 없음 (HTTP ${data.status})`,
    },
    {
      attackId: 'api_notes_list_no_token',
      expected: '로그인 토큰 없이 메모 목록을 요청하면 401로 거부되고 자료가 없어야 함',
      observed: verdict(listNoToken),
    },
    {
      attackId: 'api_notes_create_no_token',
      expected: '로그인 토큰 없이 메모 추가를 요청하면 401로 거부되어야 함',
      observed: verdict(createNoToken),
    },
    {
      attackId: 'api_notes_item_no_token',
      expected: '로그인 토큰 없이 메모 한 건의 조회·수정·삭제를 요청하면 모두 401로 거부되어야 함',
      observed: items.some(failedToSend)
        ? `요청 실패 — ${itemStatuses}`
        : items.every(rejected)
          ? `${itemStatuses} — 모두 자료 없이 거부됨`
          : `${itemStatuses} — 거부되지 않은 요청이 있음`,
    },
    {
      attackId: 'api_notes_forged_token',
      expected: '서명이 맞지 않는 위조 로그인 토큰은 401로 거부되어야 함',
      observed: verdict(forged),
    },
    {
      attackId: 'api_notes_expired_token',
      expected: '만료 시각이 지난 로그인 토큰은 401로 거부되어야 함 (이 점검의 토큰은 서명도 틀림)',
      observed: verdict(expired),
    },
    {
      attackId: 'api_notes_wrong_audience_token',
      expected: '다른 서비스용(대상이 다른) 로그인 토큰은 401로 거부되어야 함 (이 점검의 토큰은 서명도 틀림)',
      observed: verdict(otherService),
    },
    {
      attackId: 'login_normal_flow',
      expected: '정상 A 로그인 뒤 본인 메모를 추가·수정·삭제할 수 있어야 함',
      observed: '미실행 — 자동 점검에는 로그인 정보가 없어 보내지 않음',
    },
  ];
}

async function send(app, method, path, { token, body } = {}) {
  try {
    const response = await fetch(new URL(path, app), {
      method,
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* 비정상 응답 */ }
    return { status: String(response.status), json, text };
  } catch (error) {
    return { status: error.name === 'TimeoutError' ? 'timeout' : 'network_error', json: null, text: '' };
  }
}

const failedToSend = (res) => res.status === 'timeout' || res.status === 'network_error';

// 메모 내용은 기록하지 않고, 자료가 응답에 실렸는지만 판단한다.
const leaksData = (json) => (Array.isArray(json) && json.length > 0)
  || (Array.isArray(json?.notes) && json.notes.length > 0)
  || typeof json?.title === 'string' || typeof json?.id === 'string';

const rejected = (res) => res.status === '401' && !leaksData(res.json);

const verdict = (res) => {
  if (failedToSend(res)) return `요청 실패(${res.status}) — 거부 여부 확인 못 함`;
  if (rejected(res)) return 'HTTP 401, 자료 없이 거부됨';
  return `HTTP ${res.status} — 거부되지 않음${leaksData(res.json) ? ', 응답에 자료가 있음' : ''}`;
};

// 점검할 때마다 새 키로 서명하고 바로 버리는 위조 토큰이다. 서버가 이 서명을 믿으면 안 된다.
function forgedToken(issuer, claims) {
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const now = Math.floor(Date.now() / 1000);
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const head = encode({ alg: 'ES256', typ: 'JWT', kid: 'attack-check' });
  const body = encode({
    iss: issuer, aud: 'authenticated', role: 'authenticated',
    sub: crypto.randomUUID(), iat: now, exp: now + 3600, ...claims,
  });
  const signature = crypto.sign('sha256', Buffer.from(`${head}.${body}`),
    { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return `${head}.${body}.${signature}`;
}
