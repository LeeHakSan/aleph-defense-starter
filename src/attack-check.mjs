// 1~12단계 점검. 배포에 보낼 수 있는 점검은 실제 요청을 보내 그 응답으로 observed 를 만들고, 판정·탐지 규칙 점검은 배포된
// 서버의 /api/checks?case=... 가 고정된 가상 입력으로 규칙을 실행한 응답을 읽습니다. 고정 문자열로 「막음」을 적지 않습니다.
// 요청을 보내지 못한 점검, 로그인이 필요해 보내지 않은 점검은 result 를 not_run 으로 두고 observed 에 그 사실을 적습니다.
// 이 파일은 아무것도 불러오지 않고 전역 fetch·crypto 만 쓰며, 파일·환경 변수를 읽지 않습니다. 요청마다 alephEvidence 에
// 사례(caseId)와 요청 이름(requestKey)을 연결합니다(요청 헤더·URL 에는 넣지 않습니다).

const TEST_UUID = '00000000-0000-4000-8000-000000000001';
const FAKE_JWT = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.';
const TIMEOUT_MS = 5000;
const NOTE_FIELDS = /"content"\s*:|"body"\s*:|"title"\s*:/u;
// 승인 전 화면에는 로그인 폼·메모 목록·메모 요청·브라우저 저장소 사용이 없어야 한다.
const GATED_MARKERS = [['로그인 폼', /type=["']?password/iu], ['메모 목록', /id=["']notes["']/iu],
  ['메모 요청', /\/api\/notes/u], ['브라우저 저장소', /localStorage|sessionStorage|indexedDB|document\.cookie/u]];

function withTimeout(promise, ms) {
  let timer;
  const limit = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); });
  return Promise.race([promise, limit]).finally(() => clearTimeout(timer));
}

const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
const encode = (value) => base64url(new TextEncoder().encode(JSON.stringify(value)));

// 점검할 때마다 새 키로 서명하고 바로 버리는 위조 토큰이다. 서버가 이 서명을 믿으면 안 된다. 발급자를 알 수 없으면 서명 없는 토큰을 쓴다.
async function forgedToken(issuer) {
  if (typeof issuer !== 'string') return FAKE_JWT;
  try {
    const { privateKey } = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const now = Math.floor(Date.now() / 1000);
    const head = encode({ alg: 'ES256', typ: 'JWT', kid: 'attack-check' });
    const body = encode({ iss: issuer, aud: 'authenticated', role: 'authenticated', sub: crypto.randomUUID(), iat: now, exp: now + 3600 });
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(`${head}.${body}`));
    return `${head}.${body}.${base64url(signature)}`;
  } catch {
    return FAKE_JWT;
  }
}

// 요청 한 건. 응답 본문은 메모 필드가 있는지만 보고 기록하지 않는다. 요청 ID 는 응답의 x-vercel-id 끝 토큰(Vercel 기록의 Request ID 와 같다).
async function probe(ctx, caseId, requestKey, path, { method = 'GET', headers = {}, body } = {}) {
  const checkedAt = new Date().toISOString();
  try {
    const response = await withTimeout(ctx.fetch(new URL(path, ctx.base), {
      method,
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
      ...(body ? { body: JSON.stringify(body) } : {}),
      alephEvidence: { caseId, requestKey },
    }), TIMEOUT_MS + 500);
    const text = (await withTimeout(response.text(), TIMEOUT_MS)).slice(0, 60000);
    let json = null;
    try { json = JSON.parse(text); } catch { /* 화면(HTML)이나 비정상 응답 */ }
    const vercelId = response.headers?.get?.('x-vercel-id') ?? null;
    return { ran: true, method, path, requestKey, checkedAt, status: response.status, text, json,
      hasNotes: NOTE_FIELDS.test(text), requestId: vercelId ? vercelId.split('::').at(-1) : null };
  } catch (error) {
    return { ran: false, method, path, requestKey, checkedAt, status: null, error: String(error?.message || error).slice(0, 80) };
  }
}

const DENIED = new Set([401, 403, 404, 405, 503]);
const denied = (r) => r.ran && DENIED.has(r.status) && !r.hasNotes;
const gated = (r) => GATED_MARKERS.filter(([, pattern]) => pattern.test(r.text)).map(([name]) => name);
const shown = (r) => (r.ran ? `HTTP ${r.status}` : `요청 실패(${r.error})`);

function outcome(requests, check) {
  if (!requests.length || requests.some((r) => !r.ran)) {
    return { result: 'not_run', observed: requests.map(shown).join(' · ') || '요청을 보내지 못함' };
  }
  const { ok, note } = check(requests);
  return { result: ok ? 'blocked' : 'breached', observed: [requests.map(shown).join(' · '), note].filter(Boolean).join('; ') };
}

// 규칙 점검: 서버가 고정된 가상 입력으로 판정기·탐지 규칙을 실행한 응답(ready)만 읽는다. 실제 사용자·기기 상태가 아니다.
const ruleCase = (attackId, stage, expected) => ({
  attackId, stage, kind: 'rule', expected,
  async run(ctx) {
    const r = await probe(ctx, attackId, 'rule', `/api/checks?case=${attackId}`);
    if (!r.ran || r.status !== 200 || typeof r.json?.ready !== 'boolean') {
      return { requests: [r], result: 'not_run', observed: r.ran ? `HTTP ${r.status}; 규칙 점검 응답을 읽지 못함` : shown(r) };
    }
    return { requests: [r], result: r.json.ready ? 'blocked' : 'breached', observed: `HTTP ${r.status}; ready=${r.json.ready}${r.json.decision ? `; decision=${r.json.decision}` : ''}${r.json.action ? `; action=${r.json.action}` : ''}` };
  },
});

const denyCase = (attackId, stage, expected, plan) => ({
  attackId, stage, kind: 'forbidden', expected,
  async run(ctx) {
    const requests = [];
    for (const [key, path, options] of await plan(ctx)) requests.push(await probe(ctx, attackId, key, path, options));
    return { requests, ...outcome(requests, (rs) => ({ ok: rs.every(denied), note: rs.every(denied) ? '자료 없이 거부됨' : '거부되지 않은 요청이 있음' })) };
  },
});

async function issuerOf(ctx) {
  if (typeof ctx.config?.identityProvider?.issuer === 'string') return ctx.config.identityProvider.issuer;
  ctx.issuer ??= (async () => {
    const r = await probe(ctx, 's03-fake-token', 'config', '/aleph.json');
    return typeof r.json?.identityProvider?.issuer === 'string' ? r.json.identityProvider.issuer : null;
  })();
  return ctx.issuer;
}

export const CASES = [
  {
    attackId: 's01-static-notes', stage: 1, kind: 'forbidden', expected: '/data.json 에 메모가 없어야 함',
    async run(ctx) {
      const r = await probe(ctx, 's01-static-notes', 'read', '/data.json');
      const marker = typeof ctx.config?.sampleMarker === 'string' && ctx.config.sampleMarker !== '' && r.text?.includes(ctx.config.sampleMarker);
      return { requests: [r], ...outcome([r], (rs) => ({ ok: rs[0].status !== 500 && !rs[0].hasNotes && !(Array.isArray(rs[0].json?.notes) && rs[0].json.notes.length) && !marker, note: `메모 ${Array.isArray(r.json?.notes) ? r.json.notes.length : 0}건` })) };
    },
  },
  denyCase('s02-static-copy', 2, '다른 정적 사본(/notes.json)이 없어야 함', () => [['read', '/notes.json']]),
  denyCase('s03-unauth-list', 3, '로그인 없는 자기 목록 요청은 401 로 거부', () => [['read', '/api/my/notes']]),
  denyCase('s03-fake-token', 3, '서명이 틀린 위조 로그인 토큰은 401 로 거부', async (ctx) => [['forged', '/api/my/notes', { headers: { authorization: `Bearer ${await forgedToken(await issuerOf(ctx))}` } }]]),
  denyCase('s04-query-identity', 4, '쿼리로 보낸 사용자·역할은 신원으로 쓰지 않고 거부', () => [['read', `/api/my/notes?userId=${TEST_UUID}&role=instructor`]]),
  denyCase('s04-header-identity', 4, '헤더로 보낸 사용자·역할은 신원으로 쓰지 않고 거부', () => [['read', '/api/my/notes', { headers: { 'x-user-id': TEST_UUID, 'x-role': 'instructor' } }]]),
  denyCase('s05-direct-table', 5, '원본 자료 주소(/rest/v1/notes)를 이 주소로 직접 읽을 수 없어야 함', () => [['read', '/rest/v1/notes']]),
  ruleCase('s06-unregistered', 6, '미등록 기기 요청은 판정기가 거부'),
  ruleCase('s07-compound', 7, '복합 이상 요청은 판정기가 추가 확인(step_up)'),
  ruleCase('s08-unknown-route', 8, '알 수 없는 경로는 판정기가 거부'),
  ruleCase('s08-all-notes', 8, '모호한 전체 메모 목록 경로는 판정기가 거부'),
  ruleCase('s08-write-notice', 8, '강사 공지 쓰기는 판정기가 거부'),
  ruleCase('s09-burst-read', 9, '조회 폭주 사건은 탐지 규칙이 회수 제안(propose_revocation)'),
  denyCase('s10-restore-unauth', 10, '로그인 없는 복구 요청(POST /api/restore/:noteId)은 401 로 거부', () => [['read', `/api/restore/${TEST_UUID}`, { method: 'POST', body: {} }]]),
  {
    attackId: 's10-policy-copy', stage: 10, kind: 'normal', expected: '검증한 안전 정책 사본을 다시 읽어 복원할 버전과 바뀔 범위를 보여 줘야 함(읽기 전용)',
    async run(ctx) {
      const r = await probe(ctx, 's10-policy-copy', 'read', '/api/recovery-plan');
      return { requests: [r], ...outcome([r], ([x]) => ({ ok: x.status === 200 && x.json?.verified === true, note: `verified=${String(x.json?.verified)}; 복원 버전 ${x.json?.restoreVersion ?? '없음'}; 바뀔 항목 ${x.json?.changes?.length ?? '?'}개` })) };
    },
  },
  {
    attackId: 's11-approval-screen', stage: 11, kind: 'normal', expected: '첫 화면(/)은 manifest 가 연결된 승인 화면이고, 승인 전 첫 화면과 /vault.html 에는 로그인 폼·메모 목록·메모 요청·저장소 사용이 없어야 함',
    async run(ctx) {
      const home = await probe(ctx, 's11-approval-screen', 'home', '/', { headers: { accept: 'text/html' } });
      const vault = await probe(ctx, 's11-approval-screen', 'vault', '/vault.html', { headers: { accept: 'text/html' } });
      return { requests: [home, vault], ...outcome([home, vault], ([h, v]) => {
        const found = [...gated(h), ...gated(v)];
        const manifest = /rel=["']manifest["']/iu.test(h.text) && /기기 승인/u.test(h.text);
        return { ok: h.status === 200 && v.status === 200 && !found.length && manifest, note: found.length ? `검출: ${found.join(', ')}` : `승인 화면 manifest ${manifest ? '있음' : '없음'}, 로그인 폼·메모 목록·메모 요청·저장소 사용 0건` };
      }) };
    },
  },
  {
    attackId: 's11-device-status', stage: 11, kind: 'normal', expected: '서버가 확인하지 못한 기기는 승인 상태가 approved:false 이고, 로그인 없는 승인 요청도 권한을 주지 않아야 함',
    async run(ctx) {
      const status = await probe(ctx, 's11-device-status', 'status', '/api/device/status');
      const request = await probe(ctx, 's11-device-status', 'approval', '/api/device/approval', { method: 'POST', body: {} });
      return { requests: [status, request], ...outcome([status, request], ([s, a]) => ({
        ok: s.status === 200 && typeof s.json?.approved === 'boolean' && !s.hasNotes && !(a.status >= 200 && a.status < 300 && a.json?.approved === true),
        note: `approved=${String(s.json?.approved)}; connected=${String(s.json?.connected)}; 승인 요청 ${a.status}` })) };
    },
  },
  {
    attackId: 's12-operations-screen', stage: 12, kind: 'normal', expected: '작전실 화면(/operations.html)에 로그인 폼·메모 목록·메모 요청·저장소 사용과 성공 문구가 없어야 함',
    async run(ctx) {
      const r = await probe(ctx, 's12-operations-screen', 'read', '/operations.html', { headers: { accept: 'text/html' } });
      return { requests: [r], ...outcome([r], ([x]) => {
        const found = gated(x);
        return { ok: x.status === 200 && !found.length && !/통과했습니다|모두 막았습니다|방어 성공/u.test(x.text), note: found.length ? `검출: ${found.join(', ')}` : '화면 코드에 로그인 폼·메모 목록·메모 요청·저장소 사용·성공 문구 0건' };
      }) };
    },
  },
  denyCase('s12-combined-attack', 12, '무인증 조회·타인 메모 조회·서명 없는 변경·복구 요청·구역 밖 조회를 연속으로 보내도 모두 자료 없이 거부', () => [
    ['list', '/api/my/notes'],
    ['other-note-get', `/api/notes/${TEST_UUID}`],
    ['unsigned-put', `/api/notes/${TEST_UUID}`, { method: 'PUT', body: { title: '점검' } }],
    ['restore', `/api/restore/${TEST_UUID}`, { method: 'POST', body: {} }],
    ['out-of-zone', '/api/notices'],
  ]),
  {
    attackId: 's04-logged-in-cases', stage: 4, kind: 'logged_in', expected: '로그인한 B 가 A 의 메모를 조회·수정하면 거부되고, 승인된 기기의 A 가 자기 메모를 쓰는 정상 요청은 허용되어야 함',
    async run() {
      return { requests: [], result: 'not_run', observed: '미실행: 시험 계정 A·B 로그인 정보와 승인된 기기가 없어 보내지 않음' };
    },
  },
];

const MAX_ATTEMPTS = 20;

// 사례별 요청·응답을 모두 담은 관측. 작전실 화면이 이 값을 그대로 쓴다. skip 은 건너뛸 사례 ID.
export async function observeAll(input, { fetch: fetchImpl = (...args) => globalThis.fetch(...args), skip = [] } = {}) {
  const config = input !== null && typeof input === 'object' ? input : null;
  const baseUrl = typeof input === 'string' ? input : config?.publicAppUrl;
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    throw new Error('배포 주소가 올바르지 않습니다.');
  }
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || base.pathname !== '/') {
    throw new Error('배포 주소는 https 주소여야 합니다.');
  }
  const ctx = { base, fetch: fetchImpl, config };
  const rows = [];
  for (const item of CASES.filter((c) => !skip.includes(c.attackId))) {
    const measured = await item.run(ctx);
    rows.push({
      attackId: item.attackId, stage: item.stage, kind: item.kind, expected: item.expected,
      observed: measured.observed.slice(0, 300), result: measured.result,
      requests: measured.requests.map(({ method, path, requestKey, status, requestId, checkedAt }) => ({ method, path, requestKey, status, requestId, checkedAt })),
    });
  }
  return rows.sort((a, b) => a.stage - b.stage);
}

// 설정 객체나 배포 주소 문자열을 받는다. 결과는 {attackId, stage, expected, observed, result} 다섯 값뿐이다.
export async function runAttackChecks(input) {
  const rows = await observeAll(input);
  return rows.slice(0, MAX_ATTEMPTS).map(({ attackId, stage, expected, observed, result }) => ({ attackId, stage, expected, observed, result }));
}
