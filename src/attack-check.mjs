// 1~12단계 점검. 배포에 보낼 수 있는 점검은 실제 요청을 보내 그 응답으로 observed 를 만들고, 판정·탐지 규칙 점검은 배포된
// 서버의 /api/checks?case=... 가 고정된 가상 입력으로 규칙을 실행한 응답을 읽습니다. 고정 문자열로 「막음」을 적지 않습니다.
// 점검 하나(attackId)는 요청 하나만 보내고, observed 에는 심판이 확인할 수 있는 사실(HTTP 상태, 규칙 점검의 jsonReady)만 적습니다.
// 요청을 보내지 못한 점검은 network_error, 로그인이 필요해 보내지 않은 점검은 result 를 not_run(observed 도 not_run)으로 둡니다.
// 제출 묶음은 읽기 요청(GET·HEAD)만 보낼 수 있고 요청은 24건 이하여야 하므로, 이 파일은 그 두 한도를 코드로 강제한다.
// 이 파일은 아무것도 불러오지 않고 전역 fetch 만 쓰며, 파일·환경 변수를 읽지 않습니다. 요청마다 alephEvidence 에
// 사례(caseId)와 요청 이름(requestKey)을 연결합니다(요청 헤더·URL 에는 넣지 않습니다).

const TEST_UUID = '00000000-0000-4000-8000-000000000001';
const FAKE_JWT = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.';
const TIMEOUT_MS = 5000;
const READ_ONLY_METHODS = new Set(['GET', 'HEAD']);
const MAX_REQUESTS = 24;
const NOTE_FIELDS = /"content"\s*:|"body"\s*:|"title"\s*:/u;
// 승인 전 화면에는 로그인 폼·메모 목록·메모 요청·브라우저 저장소 사용이 없어야 한다.
const GATED_MARKERS = [['로그인 폼', /type=["']?password/iu], ['메모 목록', /id=["']notes["']/iu],
  ['메모 요청', /\/api\/notes/u], ['브라우저 저장소', /localStorage|sessionStorage|indexedDB|document\.cookie/u]];

function withTimeout(promise, ms) {
  let timer;
  const limit = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); });
  return Promise.race([promise, limit]).finally(() => clearTimeout(timer));
}

// 요청마다 고유한 이름(requestKey)을 만든다. 심판이 같은 요청을 사례와 이어서 관측할 때 요청끼리 겹치지 않게 한다.
function newRequestKey() {
  const id = globalThis.crypto?.randomUUID?.();
  if (id) return id;
  const hex = Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20)}`;
}

// 요청 한 건. 응답 본문은 메모 필드가 있는지만 보고 기록하지 않는다. 요청 ID 는 응답의 x-vercel-id 끝 토큰(Vercel 기록의 Request ID 와 같다).
async function probe(ctx, caseId, _label, path, { method = 'GET', headers = {} } = {}) {
  const requestKey = newRequestKey();
  const checkedAt = new Date().toISOString();
  if (!READ_ONLY_METHODS.has(method)) return { ran: false, method, path, requestKey, checkedAt, status: null, error: '읽기 요청만 보낼 수 있음' };
  ctx.sent = (ctx.sent ?? 0) + 1;
  if (ctx.sent > MAX_REQUESTS) return { ran: false, method, path, requestKey, checkedAt, status: null, error: '요청 수 한도(24건) 초과' };
  try {
    const response = await withTimeout(ctx.fetch(new URL(path, ctx.base), {
      method,
      redirect: 'manual',
      signal: AbortSignal.timeout(TIMEOUT_MS),
      headers: { accept: 'application/json', ...headers },
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

// 막음은 이 배포에 실제로 보낸 요청이 거부 응답(401·403·404·405)을 받고 메모 필드가 없을 때만이다. 서버 오류(5xx)는 응답을 얻지 못한 것이라 not_run 이다.
const DENIED = new Set([401, 403, 404, 405]);
const unreached = (r) => r.status >= 500;
const denied = (r) => r.ran && DENIED.has(r.status) && !r.hasNotes;
const gated = (r) => GATED_MARKERS.filter(([, pattern]) => pattern.test(r.text)).map(([name]) => name);
// observed 는 이 사실만 담는다: HTTP 상태, 응답 JSON 에 ready 가 있으면 jsonReady.
const facts = (r) => (r.ran ? `HTTP ${r.status}${typeof r.json?.ready === 'boolean' ? `; jsonReady=${r.json.ready}` : ''}` : 'network_error');

// 정상 요청 확인: 공격을 막은 결과가 아니므로 blocked 를 쓰지 않고 as_expected·unexpected·not_run 으로만 적는다.
function screenOutcome(request, check) {
  if (!request.ran) return { result: 'not_run', observed: 'network_error' };
  return { result: check(request) ? 'as_expected' : 'unexpected', observed: facts(request) };
}

function outcome(request, check) {
  if (!request.ran) return { result: 'not_run', observed: 'network_error' };
  if (unreached(request)) return { result: 'not_run', observed: facts(request) };
  return { result: check(request) ? 'blocked' : 'breached', observed: facts(request) };
}

// 규칙 점검(6~9단계): 서버의 /api/checks?case=<고정 ID> 가 고정된 가상 입력으로 판정기·탐지 규칙을 실행한 응답(ready)을 읽는다.
// 실제 사용자·기기 상태가 아니라 가상 조건에서 기대한 판정이 나왔다는 뜻이고, README 에도 그렇게 밝혀 둔다.
const ruleCase = (attackId, stage, expected) => ({
  attackId, stage, kind: 'rule', expected,
  async run(ctx) {
    const r = await probe(ctx, attackId, 'read', `/api/checks?case=${attackId}`);
    if (!r.ran || r.status !== 200 || typeof r.json?.ready !== 'boolean') {
      return { requests: [r], result: 'not_run', observed: facts(r) };
    }
    return { requests: [r], result: r.json.ready ? 'blocked' : 'breached', observed: facts(r) };
  },
});

// 제출 묶음은 읽기 요청(GET·HEAD)만 보낼 수 있다. 쓰기 요청이 필요한 점검은 보내지 않고 observed·result 를 not_run 으로 둔다.
const notSent = (attackId, stage, expected) => ({
  attackId, stage, kind: 'not_sent', expected,
  async run() {
    return { requests: [], result: 'not_run', observed: 'not_run' };
  },
});

const denyCase = (attackId, stage, expected, plan) => ({
  attackId, stage, kind: 'forbidden', expected,
  async run(ctx) {
    const [key, path, options] = plan(ctx);
    const request = await probe(ctx, attackId, key, path, options);
    return { requests: [request], ...outcome(request, denied) };
  },
});

// 묶음에 들어가는 점검: 점검 하나에 요청 하나. blocked 는 보낸 요청이 거부 응답을 받았거나(금지 요청) 가상 입력 규칙 점검이 jsonReady=true 일 때다.
// 41종 공격 전체는 심판이 보내는 것이라 이 파일은 그 시험을 대신하지 않는다.
export const CASES = [
  {
    attackId: 's01-static-notes', stage: 1, kind: 'forbidden', expected: '/data.json에 메모가 없음',
    async run(ctx) {
      const r = await probe(ctx, 's01-static-notes', 'read', '/data.json');
      const empty = r.ran && r.status === 200 && Array.isArray(r.json?.notes) && r.json.notes.length === 0 && !r.hasNotes;
      return { requests: [r], ...outcome(r, (x) => empty || denied(x)) };
    },
  },
  denyCase('s02-static-copy', 2, '다른 정적 사본(/notes.json)에 메모가 없음', () => ['read', '/notes.json']),
  denyCase('s03-unauth-list', 3, '로그인 없는 내 메모 목록은 거부', () => ['read', '/api/my/notes']),
  denyCase('s03-fake-token', 3, '서명이 틀린 위조 로그인 토큰은 거부', () => ['read', '/api/my/notes', { headers: { authorization: `Bearer ${FAKE_JWT}` } }]),
  denyCase('s04-query-identity', 4, '쿼리로 보낸 사용자·역할은 신원으로 쓰지 않고 거부', () => ['read', `/api/my/notes?userId=${TEST_UUID}&role=instructor`]),
  denyCase('s04-header-identity', 4, '헤더로 보낸 사용자·역할은 신원으로 쓰지 않고 거부', () => ['read', '/api/my/notes', { headers: { 'x-user-id': TEST_UUID, 'x-role': 'instructor' } }]),
  denyCase('s04-other-note', 4, '로그인 없이 남의 메모 한 건 조회 거부', () => ['read', `/api/notes/${TEST_UUID}`]),
  denyCase('s05-direct-table', 5, '배포 주소로 원본 표(/rest/v1/notes)를 직접 읽을 수 없음', () => ['read', '/rest/v1/notes']),
  ruleCase('s06-unregistered', 6, '미등록 기기 거부'),
  ruleCase('s07-compound', 7, '복합 이상 접속은 추가 확인'),
  ruleCase('s08-unknown-route', 8, '모르는 경로 거부'),
  ruleCase('s08-all-notes', 8, '전체 메모 목록 거부'),
  ruleCase('s08-write-notice', 8, '반 공지 쓰기 거부'),
  denyCase('s08-other-zone', 8, '로그인 없는 강사 공지 조회 거부', () => ['read', '/api/notices']),
  ruleCase('s09-burst-read', 9, '조회 폭주는 회수 제안'),
  ruleCase('s10-policy-verified', 10, '검증한 정책 사본이 유효함'),
  notSent('s10-restore-unauth', 10, '로그인 없는 복원 요청 거부(POST 가 필요해 보내지 않음)'),
  {
    attackId: 's11-device', stage: 11, kind: 'forbidden', expected: '로그인 없는 기기 상태는 승인 전·자료 없음',
    async run(ctx) {
      const r = await probe(ctx, 's11-device', 'read', '/api/device/status');
      return { requests: [r], ...outcome(r, (x) => x.status === 200 && x.json?.approved === false && !x.hasNotes) };
    },
  },
  denyCase('s11-unsigned-read', 11, '서명·승인 없는 읽기 요청 거부', () => ['read', `/api/notes/${TEST_UUID}`, { headers: { authorization: `Bearer ${FAKE_JWT}` } }]),
  notSent('s11-unsigned-write', 11, '서명·승인 없는 수정 요청 거부(PUT 이 필요해 보내지 않음)'),
];

// 정상 요청 확인(화면·정책·정적 자료·승인 상태): 공격을 막은 결과가 아니라서 묶음과 작전실의 점검 수치에 넣지 않고 따로 보여 준다.
export const SCREEN_CASES = [
  {
    attackId: 's10-policy-copy', stage: 10, kind: 'normal', expected: '검증한 안전 정책 사본을 다시 읽어 복원할 버전과 바뀔 범위를 보여 줘야 함(읽기 전용)',
    async run(ctx) {
      const r = await probe(ctx, 's10-policy-copy', 'read', '/api/recovery-plan');
      return { requests: [r], ...screenOutcome(r, (x) => x.status === 200 && x.json?.verified === true) };
    },
  },
  {
    attackId: 's11-approval-screen', stage: 11, kind: 'normal', expected: '첫 화면(/)은 manifest 가 연결된 승인 화면이고 승인 전에는 로그인 폼·메모 목록·메모 요청·저장소 사용이 없어야 함',
    async run(ctx) {
      const home = await probe(ctx, 's11-approval-screen', 'read', '/', { headers: { accept: 'text/html' } });
      return { requests: [home], ...screenOutcome(home, (h) => h.status === 200 && !gated(h).length && /rel=["']manifest["']/iu.test(h.text) && /기기 승인/u.test(h.text)) };
    },
  },
  {
    attackId: 's11-vault-screen', stage: 11, kind: 'normal', expected: '자료실 화면(/vault.html)은 승인 전에는 로그인 폼·메모 목록·메모 요청·저장소 사용이 없어야 함',
    async run(ctx) {
      const vault = await probe(ctx, 's11-vault-screen', 'read', '/vault.html', { headers: { accept: 'text/html' } });
      return { requests: [vault], ...screenOutcome(vault, (v) => v.status === 200 && !gated(v).length) };
    },
  },
  {
    attackId: 's12-operations-screen', stage: 12, kind: 'normal', expected: '작전실 화면(/operations.html)에 로그인 폼·메모 목록·메모 요청·저장소 사용과 성공 문구가 없어야 함',
    async run(ctx) {
      const r = await probe(ctx, 's12-operations-screen', 'read', '/operations.html', { headers: { accept: 'text/html' } });
      return { requests: [r], ...screenOutcome(r, (x) => x.status === 200 && !gated(x).length && !/통과했습니다|모두 막았습니다|방어 성공/u.test(x.text)) };
    },
  },
];

const MAX_ATTEMPTS = 20;

function context(input, fetchImpl) {
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
  return { base, fetch: fetchImpl, config };
}

async function runCases(list, ctx) {
  const rows = [];
  for (const item of list) {
    const measured = await item.run(ctx);
    rows.push({
      attackId: item.attackId, stage: item.stage, kind: item.kind, expected: item.expected,
      observed: measured.observed.slice(0, 300), result: measured.result,
      requests: measured.requests.map(({ method, path, requestKey, status, requestId, checkedAt }) => ({ method, path, requestKey, status, requestId, checkedAt })),
    });
  }
  return rows.sort((a, b) => a.stage - b.stage);
}

// 묶음과 작전실 수치가 같은 목록·같은 함수에서 나오도록 공격 점검(CASES)을 한 곳에서 실행한다. 요청은 모두 GET 이고 24건 이하(ctx.sent 로 강제).
export async function observeAll(input, { fetch: fetchImpl = (...args) => globalThis.fetch(...args) } = {}) {
  return runCases(CASES, context(input, fetchImpl));
}

// 화면·정책 확인(정상 요청). 점검 수치에 넣지 않는다. 요청 수 한도는 이 호출만 따로 센다.
export async function observeScreens(input, { fetch: fetchImpl = (...args) => globalThis.fetch(...args) } = {}) {
  return runCases(SCREEN_CASES, context(input, fetchImpl));
}

// 설정 객체나 배포 주소 문자열을 받는다. 결과는 {attackId, stage, expected, observed, result} 다섯 값뿐이다.
export async function runAttackChecks(input) {
  const rows = await observeAll(input);
  return rows.slice(0, MAX_ATTEMPTS).map(({ attackId, stage, expected, observed, result }) => ({ attackId, stage, expected, observed, result }));
}
