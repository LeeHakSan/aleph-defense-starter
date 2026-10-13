import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import checksHandler from '../api/checks/index.js';
import { publicConfig } from '../scripts/public-config.mjs';
import { RULE_CASES, detectionSummary, runRuleCheck } from '../src/rule-check.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import config from '../aleph.config.json' with { type: 'json' };

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

test('41종 공격은 표나 수치로 적지 않고 심판이 보내며 실행하지 않았다는 문장 하나로만 밝힌다', async () => {
  await assert.rejects(read('data/attack-matrix.json'));
  const html = await read('public/operations.html');
  const readme = await read('README.md');
  for (const text of [html, readme]) {
    assert.match(text, /41종 공격 전체는 심판이 보내며 이 저장소에서는 실행하지 않았습니다/u);
    assert.doesNotMatch(text, /attack-matrix|attackMatrix/u);
  }
  assert.doesNotMatch(html, /fill\('matrix'|id="matrix"/u);
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
  for (const id of ["'summary'", "'rows'", "'rule-cases'"]) assert.match(clear, new RegExp(id, 'u'));
  assert.match(clear, /replaceChildren\(\)/u);
  assert.match(html, /catch \{\s*clearAll\(/u);
  assert.match(html, /!response\.ok \|\| data\?\.error \|\| !Number\.isInteger\(data\?\.total\)/u);
});

test('작전실 화면: 막음·뚫림·정상 응답·미실행을 서로 다른 이름으로 적는다', async () => {
  const html = await read('public/operations.html');
  assert.match(html, /blocked: '막음\(기대대로\)', breached: '뚫림', as_expected: '정상 응답', unexpected: '기대와 다름', not_run: '미실행'/u);
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
    assert.equal(first.total, first.rows.length);
    assert.equal(first.total, first.blocked + first.failed + first.notRun);
    assert.equal(first.notRun, 2);
    assert.equal(first.total, 20);
    assert.equal(first.failed, 0);
    assert.equal(first.blocked, first.rows.filter(row => row.result === 'blocked').length);
    assert.deepEqual(first.attempts, first.rows.map(({ attackId, stage, expected, observed, result }) => ({ attackId, stage, expected, observed, result })));
    assert.equal('summary' in first, false);
    assert.equal('attackMatrix' in first, false);
    // total·blocked·failed·notRun 은 응답 어디에도 한 번씩만 나온다(같은 이름의 다른 수를 두지 않는다).
    const json = JSON.stringify(first);
    for (const key of ['total', 'blocked', 'failed', 'notRun']) assert.equal(json.split(`"${key}":`).length - 1, 1, key);
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
    assert.equal(response.body.total, null);
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

test('정상 요청 확인은 blocked 를 쓰지 않고, 요청 이름은 요청마다 고유하며, blocked 는 거부 응답·규칙 jsonReady·승인 전 상태만이다', async () => {
  const { observeAll, observeScreens } = await import('../src/attack-check.mjs');
  const keys = [];
  const fakeFetch = async (url, init) => {
    keys.push(init.alephEvidence.requestKey);
    const path = new URL(String(url)).pathname;
    const body = path === '/api/checks' ? { ready: true } : path === '/api/device/status' ? { approved: false, connected: false }
      : path === '/api/recovery-plan' ? { verified: true } : path === '/data.json' ? { notes: [] } : {};
    return new Response(path === '/' || path.endsWith('.html') ? '<link rel="manifest" href="/m"> 기기 승인 상태' : JSON.stringify(body),
      { status: ['/', '/vault.html', '/operations.html', '/data.json', '/api/recovery-plan', '/api/device/status', '/api/checks'].includes(path) ? 200 : 401 });
  };
  const attacks = await observeAll('https://student-defense.vercel.app', { fetch: fakeFetch });
  const screens = await observeScreens('https://student-defense.vercel.app', { fetch: fakeFetch });
  assert.ok(keys.length > 0 && new Set(keys).size === keys.length, '요청 이름이 겹친다');
  assert.ok(keys.every(key => /^[0-9a-f-]{36}$/u.test(key)), keys[0]);
  assert.equal(screens.length, 4);
  for (const row of screens) {
    assert.ok(['as_expected', 'unexpected', 'not_run'].includes(row.result), `${row.attackId}: ${row.result}`);
    assert.equal(row.requests.length, 1);
  }
  for (const row of attacks.filter(item => item.result === 'blocked')) {
    assert.match(row.observed, /^HTTP (401|403|404|405)$|^HTTP 200; jsonReady=true$|^HTTP 200$/u, `${row.attackId}: ${row.observed}`);
    if (row.observed === 'HTTP 200') assert.ok(['s01-static-notes', 's11-device'].includes(row.attackId), row.attackId);
  }
  assert.equal(JSON.stringify(screens).includes('"blocked"'), false);
});

test('작전실 화면·README·제출 설명에서 41종과 통과·막음이 한 문장에 함께 나오지 않는다', async () => {
  const pieces = [];
  for (const file of ['public/operations.html', 'README.md', 'bundle-notes.json']) {
    const text = (await read(file).catch(() => '')).replace(/<[^>]+>/gu, ' ').replace(/\\n/gu, '\n');
    for (const sentence of text.split(/[.。!?\n]/u)) pieces.push([file, sentence]);
  }
  const bad = pieces.filter(([, sentence]) => /41\s*종/u.test(sentence) && /통과|막았|막음|방어/u.test(sentence)).map(([file, sentence]) => `${file}: ${sentence.trim().slice(0, 80)}`);
  assert.deepEqual(bad, []);
  const html = await read('public/operations.html');
  assert.doesNotMatch(html.replace('위 표에 없는 공격을 통과로 적지 않습니다', ''), /통과/u);
});

test('첫 화면에도 작전실 수치 4개와 출처 표가 있고, 서버 점검 기록을 계산 없이 옮기며 승인 화면의 제한은 그대로다', async () => {
  const html = await read('public/index.html');
  for (const label of ['점검 항목', '막은 공격', '뚫린 공격', '실행하지 않은 점검']) assert.match(html, new RegExp(`<dt>${label}</dt>`, 'u'));
  for (const key of ['total', 'blocked', 'failed', 'notRun']) assert.match(html, new RegExp(`data-k="${key}"`, 'u'));
  assert.match(html, /fetch\('\/api\/checks'/u);
  assert.match(html, /!Number\.isInteger\(data\?\.total\)/u);
  assert.match(html, /<dt>학생이 만든 것<\/dt>/u);
  assert.match(html, /<dt>제공 엔진<\/dt>/u);
  // 11단계 제한: 승인 전 화면에는 로그인 폼·메모 목록·메모 요청·브라우저 저장소가 없다.
  assert.doesNotMatch(html, /type=["']?password/iu);
  assert.doesNotMatch(html, /id=["']notes["']/u);
  assert.doesNotMatch(html, /\/api\/notes/u);
  assert.doesNotMatch(html, /localStorage|sessionStorage|indexedDB|document\.cookie/u);
  assert.doesNotMatch(html, /innerHTML|insertAdjacentHTML|eval\(/u);
});

test('점검 기록에 학생 몫과 제공 엔진(ALEPH SDP 엔진)의 출처가 붙는다', async () => {
  const { SOURCES, ENGINE } = await import('../src/sources.mjs');
  assert.equal(ENGINE, 'ALEPH SDP 엔진');
  assert.equal(SOURCES.engine.name, ENGINE);
  assert.ok(SOURCES.student.parts.some(part => part.includes('src/decider.mjs')));
  assert.match(SOURCES.engine.role, /미실행/u);
  const { operationsStatus } = await import('../src/operations.mjs');
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ ready: true }), { status: 401 });
  try {
    const record = await operationsStatus({ now: 20_000_000 });
    assert.deepEqual(record.sources, SOURCES);
  } finally {
    globalThis.fetch = original;
  }
});

test('규칙 점검 응답은 학생 작업 출처와 제공 엔진을 밝히고 엔진 집행은 미실행으로 적는다', async () => {
  for (const id of [...Object.keys(RULE_CASES), 's09-burst-read', 's10-policy-verified']) {
    const result = await runRuleCheck(id);
    assert.equal(result.engine, 'ALEPH SDP 엔진', id);
    assert.equal(result.engineEnforced, 'not_run', id);
    assert.match(result.source, /^학생 (판정기|탐지 규칙|안전 정책 사본)\(/u, id);
  }
});
