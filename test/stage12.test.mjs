import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import checksHandler from '../api/checks/index.js';
import { publicConfig } from '../scripts/public-config.mjs';
import { RULE_CASES, detectionSummary, runRuleCheck } from '../src/rule-check.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import matrix from '../data/attack-matrix.json' with { type: 'json' };

const read = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

function fakeResponse() {
  return {
    headers: {}, code: null, body: null,
    setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
  };
}
const callChecks = async (request) => {
  const response = fakeResponse();
  await checksHandler(request, response);
  return response;
};

test('규칙 점검: 고정된 가상 입력으로 판정기·탐지를 실행하고 기대한 결과가 ready:true', async () => {
  for (const id of [...Object.keys(RULE_CASES), 's09-burst-read']) {
    const result = await runRuleCheck(id);
    assert.equal(result.ready, true, id);
  }
  assert.equal((await runRuleCheck('s06-unregistered')).decision, 'deny');
  assert.equal((await runRuleCheck('s07-compound')).decision, 'step_up');
  assert.equal((await runRuleCheck('s09-burst-read')).action, 'propose_revocation');
});

test('규칙 점검: 알 수 없는 사례·위험한 이름·형식이 틀린 값은 실행하지 않고 null', async () => {
  for (const id of ['', 'nope', '__proto__', 'constructor', 'toString', 'hasOwnProperty', 's06-unregistered ', 'S06-UNREGISTERED', undefined, null, 7, ['s06-unregistered'], {}]) {
    assert.equal(await runRuleCheck(id), null, String(id));
  }
});

test('점검 API: ?case= 는 규칙 점검, 알 수 없으면 400, GET 이 아니면 405, 캐시하지 않는다', async () => {
  const ok = await callChecks({ method: 'GET', query: { case: 's08-write-notice' } });
  assert.equal(ok.code, 200);
  assert.equal(ok.body.ready, true);
  assert.equal(ok.headers['cache-control'], 'no-store');
  assert.match(ok.headers['content-type'], /application\/json/u);
  assert.equal((await callChecks({ method: 'GET', query: { case: 'drop table notes' } })).code, 400);
  assert.deepEqual((await callChecks({ method: 'GET', query: { case: '__proto__' } })).body, { error: 'unknown_check' });
  const post = await callChecks({ method: 'POST', query: { case: 's06-unregistered' } });
  assert.equal(post.code, 405);
  assert.equal(post.headers.allow, 'GET');
});

test('탐지 요약은 가상 사건(local_fixture)이고 120건은 관찰, 121건은 회수 제안', () => {
  const summary = detectionSummary();
  assert.equal(summary.source, 'local_fixture');
  assert.deepEqual(summary.cases.map(item => [item.events, item.action]), [[120, 'observe'], [121, 'propose_revocation']]);
});

test('41종 시험표: 41종이고 실행하지 않은 것을 통과로 바꿔 두지 않았다', () => {
  const items = matrix.attacks;
  assert.equal(items.length, 41);
  assert.equal(new Set(items.map(item => item.name)).size, 41);
  assert.deepEqual(items.map(item => item.no), Array.from({ length: 41 }, (_, i) => i + 1));
  assert.equal(items.filter(item => item.status === 'executed').length, 0);
  for (const item of items) {
    assert.ok(['not_run', 'executed'].includes(item.status), item.name);
    assert.equal(typeof item.note, 'string');
    assert.ok(item.note.length > 0);
  }
  const known = items.filter(item => item.stage !== null);
  assert.equal(known.length, 17);
  assert.deepEqual([...new Set(known.map(item => item.stage))].sort((a, b) => a - b), [8, 9, 10, 11, 12]);
  assert.ok(items.filter(item => item.stage === null).every(item => item.attack === null));
  assert.match(matrix.rule, /not_run/u);
});

test('시험표가 가리키는 관련 점검은 실제로 있는 점검 ID 이다', async () => {
  const { CASES, SCREEN_CASES } = await import('../src/attack-check.mjs');
  const ids = new Set([...CASES, ...SCREEN_CASES].map(item => item.attackId));
  for (const item of matrix.attacks) for (const id of item.relatedCases) assert.ok(ids.has(id), `${item.name}: ${id}`);
});

test('작전실 화면: 서버 응답만 글자로 그리고, 로그인 폼·메모 목록·메모 요청·저장소 사용·성공 문구가 없다', async () => {
  const html = await read('public/operations.html');
  assert.match(html, /\/api\/checks/u);
  assert.doesNotMatch(html, /type=["']?password/iu);
  assert.doesNotMatch(html, /id=["']notes["']/u);
  assert.doesNotMatch(html, /\/api\/notes/u);
  assert.doesNotMatch(html, /localStorage|sessionStorage|indexedDB|document\.cookie/u);
  assert.doesNotMatch(html, /통과했습니다|모두 막았습니다|방어 성공/u);
  assert.doesNotMatch(html, /innerHTML|insertAdjacentHTML|outerHTML|document\.write|eval\(/u);
  assert.match(html, /rel="manifest"/u);
  assert.match(html, /미실행/u);
});

test('작전실 화면: 관측에 실패하면 이전 수치와 표를 비운다', async () => {
  const html = await read('public/operations.html');
  const clear = html.slice(html.indexOf('function clearAll'), html.indexOf('function render'));
  for (const id of ["'summary'", "'rows'", "'rule-cases'", "'matrix'"]) assert.match(clear, new RegExp(id, 'u'));
  assert.match(clear, /replaceChildren\(\)/u);
  assert.match(html, /catch \{\s*clearAll\(/u);
  assert.match(html, /!response\.ok \|\| data\?\.error \|\| !data\?\.summary/u);
});

test('작전실 화면: 결과 문구는 기대와 같음·기대와 다름·미실행뿐이고 색만으로 의미를 전하지 않는다', async () => {
  const html = await read('public/operations.html');
  assert.match(html, /blocked: '기대와 같음', breached: '기대와 다름', not_run: '미실행'/u);
  assert.match(html, /span\.textContent = RESULT\[result\]/u);
});

test('공개 설정 사본: 운영 측 형식(객체 경로)이고 비밀값 없이 원본의 값만 옮긴다', () => {
  const copy = publicConfig(config);
  assert.equal(copy.schema, 'aleph.config.v1');
  assert.equal(copy.step, config.step);
  assert.equal(copy.repoUrl, config.repoUrl);
  assert.equal(copy.restoreRoute, '/api/restore/:noteId');
  assert.equal(copy.originalApiUrl, config.originalApiUrl);
  assert.deepEqual(copy.allowedRoutes, [
    { service: 'notes', method: 'GET', pathPattern: '/api/my/notes', zone: 'my-notes' },
    { service: 'notes', method: 'GET', pathPattern: '/api/notes/:id', zone: 'my-notes' },
    { service: 'notes', method: 'GET', pathPattern: '/notes/:id', zone: 'my-notes' },
  ]);
  assert.deepEqual(Object.keys(copy).sort(), ['allowedRoutes', 'originalApiUrl', 'repoUrl', 'restoreRoute', 'schema', 'step']);
  assert.doesNotMatch(JSON.stringify(copy), /eyJ|sb_secret|service_role|judgeIssuer|identityProvider|sampleMarker/u);
  assert.throws(() => publicConfig({ ...config, allowedRoutes: ['not a route'] }));
});

test('표준 진입점: npm test 와 npm run check 가 있고 check 는 묶음 스크립트와 같다', async () => {
  const pkg = JSON.parse(await read('package.json'));
  assert.equal(pkg.scripts.test, 'node --test test/*.test.mjs');
  assert.equal(pkg.scripts.check, 'node scripts/bundle.mjs');
  assert.equal(pkg.scripts.bundle, pkg.scripts.check);
  assert.equal(pkg.type, 'module');
});

test('묶음 스크립트는 운영 측 현재 규칙대로 배포 주소를 넘기고 다섯 값·checkedAt 을 요구한다', async () => {
  const bundle = await read('scripts/bundle.mjs');
  assert.match(bundle, /await runAttackChecks\(config\.publicAppUrl\)/u);
  assert.match(bundle, /'attackId,expected,observed,result,stage'/u);
  assert.match(bundle, /\['blocked', 'breached', 'not_run'\]/u);
  assert.match(bundle, /checkedAt: new Date\(\)\.toISOString\(\)/u);
  assert.doesNotMatch(bundle, /runAttackChecks\(config\)/u);
});

test('설정: 12단계이고 판정기 규칙 이름이 작전실과 같은 출처(RULE_IDS)다', async () => {
  assert.equal(config.step, 12);
  const operations = await read('src/operations.mjs');
  assert.match(operations, /ruleIds: \[\.\.\.RULE_IDS\]/u);
  assert.ok(RULE_IDS.length >= 5);
});

test('서버 점검 경로·작전실 코드에 메모 본문·토큰·기기 키를 읽는 코드가 없다', async () => {
  for (const file of ['api/checks/index.js', 'src/operations.mjs', 'src/rule-check.mjs']) {
    const source = (await read(file)).replace(/\/\/.*$/gmu, '');
    assert.doesNotMatch(source, /authorization|SUPABASE_SECRET|from\('notes'\)|\.rpc\(|createClient|localStorage/iu, file);
  }
});

test('작전실 API: 실제 요청 ID·확인 시각·미실행을 구분해 담고 메모 본문이나 토큰은 담지 않는다', async () => {
  const { operationsStatus } = await import('../src/operations.mjs');
  const original = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url) => {
    const { pathname } = new URL(String(url));
    seen.push(pathname);
    const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'x-vercel-id': 'iad1::sfo1::reqid-1700000000000-aaaabbbbcccc' } });
    if (pathname === '/api/checks') return json(200, { ready: true, decision: 'deny' });
    if (pathname === '/api/device/status') return json(200, { approved: false, connected: false });
    if (pathname === '/api/recovery-plan') return json(200, { verified: true, restoreVersion: 1, changes: [] });
    if (pathname === '/data.json') return json(200, { notes: [] });
    if (pathname === '/aleph.json') return json(200, {});
    if (pathname === '/' || pathname === '/vault.html') return new Response('<link rel="manifest" href="/m"> 기기 승인 상태', { status: 200 });
    return json(401, { error: 'LOGIN_REQUIRED' });
  };
  try {
    const first = await operationsStatus({ now: 1_000_000 });
    assert.equal(first.schema, 'aleph.operations.v1');
    assert.equal(first.cached, false);
    assert.equal(first.step, 12);
    assert.equal(first.summary.total, first.rows.length);
    assert.equal(first.summary.total, first.summary.blocked + first.summary.breached + first.summary.notRun);
    assert.equal(first.summary.notRun, 1);
    assert.equal(first.summary.breached, 0);
    assert.equal(first.summary.blocked, first.rows.filter(row => row.result === 'blocked').length);
    assert.equal(first.summary.blocked, first.summary.total - first.summary.notRun - first.summary.breached);
    const request = first.rows.find(row => row.attackId === 's03-unauth-list').requests[0];
    assert.equal(request.requestId, 'reqid-1700000000000-aaaabbbbcccc');
    assert.match(request.checkedAt, /^\d{4}-\d\d-\d\dT/u);
    // 작전실 수치는 묶음과 같은 함수·같은 점검 목록에서 나오고, 화면·정책 확인은 점검 수치에 넣지 않고 따로 둔다.
    const { CASES, SCREEN_CASES } = await import('../src/attack-check.mjs');
    assert.deepEqual(first.rows.map(row => row.attackId).sort(), CASES.map(item => item.attackId).sort());
    assert.equal(first.rows.every(row => row.requests.length <= 1), true);
    assert.deepEqual(first.screens.map(row => row.attackId).sort(), SCREEN_CASES.map(item => item.attackId).sort());
    assert.equal(first.rows.some(row => first.screens.some(screen => screen.attackId === row.attackId)), false);
    assert.equal(first.revocation.connected, false);
    assert.equal(first.revocation.revoked, null);
    assert.equal(first.recovery.memoBackups.state, 'not_run');
    assert.equal(first.attackMatrix.total, 41);
    assert.equal(first.attackMatrix.executed, 0);
    assert.equal(first.attackMatrix.items.length, 41);
    assert.equal(first.detection.source, 'local_fixture');
    assert.deepEqual(first.judgeRules.ruleIds, [...RULE_IDS]);
    const text = JSON.stringify(first);
    assert.doesNotMatch(text, /eyJ[\w-]{10,}\.|Bearer\s+\S{12,}|SUPABASE|sb_secret|"title"|"content"|"body"/u);

    const requestsBefore = seen.length;
    const again = await operationsStatus({ now: 1_005_000 });
    assert.equal(again.cached, true);
    assert.equal(again.checkedAt, first.checkedAt);
    assert.equal(seen.length, requestsBefore);
  } finally {
    globalThis.fetch = original;
  }
});

test('작전실 API: 관측이 실패하면 이전 성공 값을 돌려주지 않고 실패를 알린다', async () => {
  const { operationsStatus } = await import('../src/operations.mjs');
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 401 });
  try {
    await operationsStatus({ now: 9_000_000 });
  } catch { /* 아래에서 확인 */ }
  globalThis.fetch = original;
  const response = await callChecks({ method: 'GET', query: {} });
  assert.ok([200, 503].includes(response.code));
  if (response.code === 503) {
    assert.equal(response.body.error, 'observation_failed');
    assert.deepEqual(response.body.rows, []);
    assert.equal(response.body.summary, null);
  }
});

test('제출 묶음 점검은 읽기 요청(GET·HEAD)만 보내고 요청은 24건 이하이며 사례마다 요청 이름이 겹치지 않는다', async () => {
  const { observeAll, CASES } = await import('../src/attack-check.mjs');
  const calls = [];
  const fakeFetch = async (url, init) => { calls.push({ url: String(url), init }); return new Response('{}', { status: 401 }); };
  await observeAll('https://student-defense.vercel.app', { fetch: fakeFetch });
  assert.ok(calls.length >= 1 && calls.length <= 24, `요청 ${calls.length}건`);
  for (const { url, init } of calls) {
    assert.ok(['GET', 'HEAD'].includes(init.method), `${init.method} ${url}`);
    assert.equal(init.body, undefined, url);
    assert.equal(Object.keys(init.headers).some(key => key.toLowerCase() === 'content-type'), false, url);
  }
  // 설정 객체로 불러도 같은 한도를 지킨다(위조 토큰 서명용 발급자만 더해질 뿐 요청은 늘지 않는다).
  const withConfig = [];
  await observeAll({ publicAppUrl: 'https://student-defense.vercel.app', identityProvider: { issuer: 'https://p.supabase.co/auth/v1' } },
    { fetch: async (url, init) => { withConfig.push(init.method); return new Response('{}', { status: 401 }); } });
  assert.ok(withConfig.length <= 24 && withConfig.every(method => method === 'GET'));
  assert.ok(CASES.length <= 20);
});

test('점검 코드가 쓰는 한도: 읽기 전용이 아닌 요청과 25번째 요청은 아예 보내지 않는다', async () => {
  const source = await read('src/attack-check.mjs');
  assert.match(source, /READ_ONLY_METHODS = new Set\(\['GET', 'HEAD'\]\)/u);
  assert.match(source, /MAX_REQUESTS = 24/u);
  assert.doesNotMatch(source.replace(/\/\/.*$/gmu, ''), /method: '(POST|PUT|PATCH|DELETE)'/u);
  assert.doesNotMatch(source.replace(/\/\/.*$/gmu, ''), /JSON\.stringify\(body\)/u);
});
