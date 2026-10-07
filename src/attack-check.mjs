import crypto from 'node:crypto';

// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 5) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
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

  const aleph = await send(app, 'GET', '/aleph.json');
  const page = await send(app, 'GET', '/');

  // 화면에는 공개 키가 없으므로 직접 읽기 점검의 공개 키는 실행하는 사람이 환경 변수로 준다. 값은 어디에도 기록하지 않는다.
  const publicKey = usablePublicKey(process.env.ALEPH_PUBLIC_KEY ?? process.env.SUPABASE_PUBLISHABLE_KEY);
  const originalUrl = typeof config.originalApiUrl === 'string' ? config.originalApiUrl : null;
  const anonRead = publicKey && originalUrl
    ? await sendDirect(`${originalUrl}?select=id,title,content`, publicKey)
    : null;

  const routes = Array.isArray(aleph.json?.allowedRoutes) ? aleph.json.allowedRoutes : [];
  const keyLike = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|sb_(?:publishable|secret)_[A-Za-z0-9_-]{8,}/gu;
  const serverSecret = /sb_secret_|service_role|SUPABASE_SECRET_KEY/u;
  const leaked = [['/', page], ['/data.json', data]].filter(([, file]) => serverSecret.test(file.text)
    || (typeof config.sampleMarker === 'string' && file.text.includes(config.sampleMarker)));

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
      attackId: 'aleph_json_allowed_routes',
      expected: '/aleph.json의 allowedRoutes에 허용 경로가 하나 이상 있어야 함',
      observed: failedToSend(aleph)
        ? `요청 실패(${aleph.status}) — 확인 못 함`
        : `/aleph.json에 허용 경로 ${routes.length}개 (HTTP ${aleph.status})`,
    },
    {
      attackId: 'page_no_public_key',
      expected: '첫 화면 코드에 Supabase 공개 키가 없어야 함 (키는 서버 함수에만 둠)',
      observed: failedToSend(page)
        ? `요청 실패(${page.status}) — 확인 못 함`
        : `첫 화면 코드에 키 모양 문자열 ${(page.text.match(keyLike) ?? []).length}개 (HTTP ${page.status})`,
    },
    {
      attackId: 'public_files_no_server_key_or_seed',
      expected: '공개 정적 파일(첫 화면, /data.json)에 서버 전용 키 이름·값과 시드 표식이 없어야 함',
      observed: failedToSend(page) || failedToSend(data)
        ? '요청 실패 — 확인 못 함'
        : leaked.length
          ? `${leaked.map(([path]) => path).join(', ')}에서 서버 전용 키 또는 시드 표식이 검출됨`
          : '첫 화면과 /data.json에서 검출 0건',
    },
    {
      attackId: 'data_api_anon_direct_read',
      expected: '공개 키로 원본 자료 주소(originalApiUrl)를 직접 읽어도 메모 행이 한 건도 오지 않아야 함',
      observed: !anonRead
        ? '미실행 — 점검에 쓸 공개 키(환경 변수 ALEPH_PUBLIC_KEY)가 없음'
        : failedToSend(anonRead)
          ? `요청 실패(${anonRead.status}) — 확인 못 함`
          : anonRead.rows > 0
            ? `HTTP ${anonRead.status} — 메모 ${anonRead.rows}건이 직접 읽힘`
            : `HTTP ${anonRead.status}, 메모 행 0건`,
    },
    {
      attackId: 'api_notes_other_owner',
      expected: '로그인한 B가 A의 메모를 조회·수정·삭제하면 403으로 거부되고 A의 메모는 그대로여야 함',
      observed: '미실행 — 자동 점검에는 시험 계정 로그인 정보가 없어 보내지 않음',
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

// 공개용 키(role이 anon인 JWT 또는 sb_publishable_)만 쓴다. 서버 전용 키가 잘못 들어오면 쓰지 않는다.
function usablePublicKey(value) {
  if (typeof value !== 'string') return null;
  if (/^sb_publishable_[A-Za-z0-9_-]+$/u.test(value)) return value;
  try {
    return JSON.parse(Buffer.from(value.split('.')[1], 'base64url')).role === 'anon' ? value : null;
  } catch {
    return null;
  }
}

// 메모 내용은 기록하지 않고 행 수만 센다.
async function sendDirect(url, anonKey) {
  try {
    const response = await fetch(url, {
      redirect: 'error',
      signal: AbortSignal.timeout(10000),
      headers: { apikey: anonKey, authorization: `Bearer ${anonKey}` },
    });
    const json = await response.json().catch(() => null);
    return { status: String(response.status), rows: Array.isArray(json) ? json.length : 0 };
  } catch (error) {
    return { status: error.name === 'TimeoutError' ? 'timeout' : 'network_error', rows: 0 };
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
