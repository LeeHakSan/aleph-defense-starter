import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { observeAll, runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 1,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 1,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('build identity lists the allowed routes from the config', () => {
  const routes = ['GET /api/notes', 'POST /api/notes', 'GET /api/notes/:id', 'POST /api/auth/login'];
  assert.deepEqual(deploymentIdentity(env, { ...config, allowedRoutes: routes }).allowedRoutes, routes);
  assert.equal('allowedRoutes' in deploymentIdentity(env, config), false);
  assert.equal('allowedRoutes' in deploymentIdentity(env, { ...config, allowedRoutes: [] }), false);
  assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes: ['not a route'] }));
  assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes: 'GET /api/notes' }));
});

test('build identity publishes the original api url only as a plain https path', () => {
  const url = 'https://project.supabase.co/rest/v1/notes';
  assert.equal(deploymentIdentity(env, { ...config, originalApiUrl: url }).originalApiUrl, url);
  assert.equal('originalApiUrl' in deploymentIdentity(env, config), false);
  assert.equal('originalApiUrl' in deploymentIdentity(env, { ...config, originalApiUrl: null }), false);
  for (const bad of ['http://project.supabase.co/rest/v1/notes', `${url}?select=*`, `${url}?`, `${url}#x`,
    'https://user:pw@project.supabase.co/rest/v1/notes', 'https://localhost/rest/v1/notes', 'not a url', '', 5]) {
    assert.throws(() => deploymentIdentity(env, { ...config, originalApiUrl: bad }), undefined, String(bad));
  }
});

const APP = 'https://student-defense.vercel.app';
const ATTEMPT_KEYS = 'attackId,expected,observed,result,stage';

// 보호가 풀린 배포를 흉내 낸다: 모든 경로가 메모를 돌려주고 로그인 폼이 있는 화면을 준다.
function openFetch(calls) {
  return async (url, init) => {
    calls.push({ url: String(url), init });
    const path = new URL(String(url)).pathname;
    const html = path === '/' || path.endsWith('.html');
    return new Response(html ? '<input type="password" id="pw"><ul id="notes"></ul><script>fetch("/api/notes")</script>'
      : JSON.stringify({ ready: false, approved: true, verified: false, notes: [{ title: '가상' }], title: '가상', content: '가상', identityProvider: { issuer: 'https://project.supabase.co/auth/v1' } }),
    { status: 200, headers: { 'content-type': html ? 'text/html' : 'application/json', 'x-vercel-id': 'iad1::abc12-1700000000000-feedfacecafe' } });
  };
}

// 정상 배포를 흉내 낸다: 보호 경로는 401, 규칙 점검은 ready:true, 승인 화면은 정적 안내만 있다.
function safeFetch(calls) {
  return async (url, init) => {
    calls.push({ url: String(url), init });
    const { pathname, searchParams } = new URL(String(url));
    const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'x-vercel-id': 'iad1::abc12-1700000000000-feedfacecafe' } });
    if (pathname === '/api/checks') return json(200, { ready: true, decision: 'deny', action: 'propose_revocation' });
    if (pathname === '/api/device/status') return json(200, { approved: false, connected: false });
    if (pathname === '/api/device/approval') return json(503, { error: 'device_verification_unavailable' });
    if (pathname === '/api/recovery-plan') return json(200, { verified: true, restoreVersion: 1, changes: [] });
    if (pathname === '/aleph.json') return json(200, { identityProvider: { issuer: 'https://project.supabase.co/auth/v1' } });
    if (pathname === '/data.json') return json(200, { notes: [] });
    if (pathname === '/') return new Response('<link rel="manifest" href="/m"><h2>기기 승인 상태</h2>', { status: 200, headers: { 'content-type': 'text/html' } });
    if (pathname === '/vault.html' || pathname === '/operations.html') return new Response('<main>안내만 있습니다</main>', { status: 200, headers: { 'content-type': 'text/html' } });
    if (pathname === '/notes.json' || pathname.startsWith('/rest/')) return json(404, { error: 'NOT_FOUND' });
    void searchParams;
    return json(401, { error: 'LOGIN_REQUIRED' });
  };
}

test('점검은 배포 주소 문자열이나 설정 객체를 받아 다섯 값만 돌려주고 20개를 넘지 않는다', async () => {
  for (const input of [APP, { publicAppUrl: APP, step: 12, sampleMarker: 'SAMPLE_NOTE_1' }]) {
    const calls = [];
    const attempts = await observeAndRun(input, safeFetch(calls));
    assert.ok(attempts.length >= 1 && attempts.length <= 20, String(attempts.length));
    for (const attempt of attempts) {
      assert.equal(Object.keys(attempt).sort().join(','), ATTEMPT_KEYS);
      assert.match(attempt.attackId, /^[a-z0-9][a-z0-9_.-]{0,79}$/iu);
      assert.ok(Number.isInteger(attempt.stage) && attempt.stage >= 1 && attempt.stage <= 12);
      assert.ok(['blocked', 'breached', 'not_run'].includes(attempt.result));
      assert.ok(attempt.expected.length > 0 && attempt.expected.length <= 300);
      assert.ok(attempt.observed.length > 0 && attempt.observed.length <= 300);
    }
    assert.equal(new Set(attempts.map(attempt => attempt.attackId)).size, attempts.length);
  }
});

test('정상 배포: 거부해야 할 요청은 blocked, 로그인이 필요한 점검은 보내지 않고 not_run 으로 둔다', async () => {
  const attempts = await observeAndRun(APP, safeFetch([]));
  const byId = Object.fromEntries(attempts.map(attempt => [attempt.attackId, attempt]));
  for (const id of ['s03-unauth-list', 's03-fake-token', 's12-unauth-list']) {
    assert.equal(byId[id].result, 'blocked', `${id}: ${byId[id].observed}`);
  }
  assert.equal(byId['s12-other-user-read'].result, 'not_run');
  assert.equal(byId['s12-other-user-read'].observed, 'not_run');
  assert.equal(attempts.some(attempt => attempt.result === 'breached'), false);
});

test('보호가 풀린 배포: 같은 점검이 breached 로 표시되고 고정 문자열로 막음을 적지 않는다', async () => {
  const attempts = await observeAndRun(APP, openFetch([]));
  const byId = Object.fromEntries(attempts.map(attempt => [attempt.attackId, attempt]));
  for (const id of ['s03-unauth-list', 's03-fake-token', 's12-unauth-list']) {
    assert.equal(byId[id].result, 'breached', `${id}: ${byId[id].observed}`);
  }
  assert.match(byId['s03-unauth-list'].observed, /^HTTP 200/u);
});

test('심판이 확인할 수 있는 사실만 observed 에 적는다: HTTP 상태와 규칙 점검의 jsonReady, 요청이 없으면 not_run', async () => {
  for (const make of [safeFetch, openFetch]) {
    const attempts = await observeAndRun(APP, make([]));
    for (const attempt of attempts) {
      assert.match(attempt.observed, /^(HTTP \d{3}(; jsonReady=(true|false))?|network_error|not_run)$/u, `${attempt.attackId}: ${attempt.observed}`);
    }
  }
  const byId = Object.fromEntries((await observeAndRun(APP, safeFetch([]))).map(attempt => [attempt.attackId, attempt]));
  assert.equal(byId['s03-unauth-list'].observed, 'HTTP 401');
});

test('점검 하나(attackId)에는 요청을 하나만 보내고, 모든 요청은 GET 이며 24건 이하다', async () => {
  const calls = [];
  await observeAndRun(APP, safeFetch(calls));
  const perCase = Object.groupBy(calls, ({ init }) => init.alephEvidence.caseId);
  for (const [caseId, list] of Object.entries(perCase)) assert.equal(list.length, 1, `${caseId}: 요청 ${list.length}건`);
  assert.ok(calls.length <= 24);
  assert.ok(calls.every(({ init }) => init.method === 'GET'));
});

test('요청을 보내지 못하면 막음으로 세지 않고 not_run 으로 남긴다', async () => {
  const attempts = await observeAndRun(APP, async () => { throw new Error('network down'); });
  const sent = attempts.filter(attempt => attempt.attackId !== 's04-logged-in-cases');
  assert.ok(sent.length > 0);
  assert.ok(sent.every(attempt => attempt.result === 'not_run'), JSON.stringify(sent.map(a => a.result)));
  assert.ok(attempts.every(attempt => attempt.result !== 'blocked'));
});

test('요청마다 alephEvidence 에 사례와 요청 이름을 연결하고 헤더·URL 에는 넣지 않는다', async () => {
  const calls = [];
  await observeAndRun(APP, safeFetch(calls));
  assert.ok(calls.length >= 3 && calls.length <= 24, String(calls.length));
  for (const { url, init } of calls) {
    assert.equal(typeof init.alephEvidence?.caseId, 'string', url);
    assert.equal(typeof init.alephEvidence?.requestKey, 'string', url);
    assert.doesNotMatch(url, /alephEvidence|caseId|requestKey/u);
    assert.equal(Object.keys(init.headers).some(key => /aleph|evidence/iu.test(key)), false);
    assert.equal(init.redirect, 'manual');
  }
});

test('점검은 로그인 토큰·키를 보내지 않고 위조 토큰은 서명이 없는 가짜 토큰이다', async () => {
  const calls = [];
  await observeAndRun(APP, safeFetch(calls));
  const auth = calls.map(({ init }) => init.headers.authorization).filter(Boolean);
  assert.equal(auth.length, 1);
  assert.ok(auth[0].startsWith('Bearer '));
  assert.equal(auth[0].slice('Bearer '.length).split('.').length, 3);
  assert.equal(calls.some(({ url }) => /^https:\/\/(?!student-defense)/u.test(url)), false);
});

test('잘못된 배포 주소는 요청을 보내기 전에 거부한다', async () => {
  for (const bad of ['http://student-defense.vercel.app', 'not a url', `https://user:pw${'@'}student-defense.vercel.app`, `${APP}/x`, `${APP}?a=1`, undefined, 42]) {
    await assert.rejects(observeAll(bad, { fetch: async () => { throw new Error('요청이 나가면 안 됨'); } }), undefined, String(bad));
  }
});

test('점검 파일은 아무것도 불러오지 않고 파일·환경 변수를 읽지 않는다', async () => {
  const source = (await readFile(new URL('../src/attack-check.mjs', import.meta.url), 'utf8')).replace(/\/\/.*$/gmu, '');
  assert.doesNotMatch(source, /^\s*import\s|\brequire\s*\(|import\s*\(|process\.|node:|readFile/mu);
});

async function observeAndRun(input, fetchImpl) {
  const original = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await runAttackChecks(input);
  } finally {
    globalThis.fetch = original;
  }
}

test('blocked 는 실제로 거부 응답(401·403·404 등)을 받았거나 규칙 점검이 jsonReady=true 일 때만이고, 200 으로 열린 정상 응답은 공격 점검에 없다', async () => {
  const { CASES, SCREEN_CASES } = await import('../src/attack-check.mjs');
  const attackIds = CASES.map(item => item.attackId);
  for (const id of ['s01-static-notes', 's11-device-status', 's10-policy-copy', 's11-approval-screen', 's11-vault-screen', 's12-operations-screen']) {
    assert.equal(attackIds.includes(id), false, `${id} 는 정상 요청 확인이라 공격 점검에 넣지 않는다`);
    assert.ok(SCREEN_CASES.some(item => item.attackId === id), id);
  }
  // 모든 요청이 200 으로 열리는 배포에서는 거부 점검이 blocked 로 남을 수 없다.
  const attempts = await observeAndRun(APP, openFetch([]));
  const claimed = attempts.filter(attempt => attempt.result === 'blocked');
  for (const attempt of claimed) {
    assert.match(attempt.observed, /^HTTP (401|403|404|405|503)$|jsonReady=true$/u, `${attempt.attackId}: ${attempt.observed}`);
  }
  // 정상 배포에서도 blocked 로 센 점검은 모두 거부 응답이거나 jsonReady=true 이다.
  const safe = await observeAndRun(APP, safeFetch([]));
  for (const attempt of safe.filter(item => item.result === 'blocked')) {
    assert.match(attempt.observed, /^HTTP (401|403|404|405|503)$|jsonReady=true$/u, `${attempt.attackId}: ${attempt.observed}`);
  }
  assert.equal(safe.filter(item => item.result === 'not_run').every(item => item.observed === 'not_run'), true);
});

test('가상 입력 규칙 점검은 실제 공격 실행이 아니라서 묶음의 공격 점검에 없고 blocked 로 세지 않는다', async () => {
  const { CASES, RULE_CHECKS, observeRules } = await import('../src/attack-check.mjs');
  const attackIds = new Set(CASES.map(item => item.attackId));
  for (const item of RULE_CHECKS) assert.equal(attackIds.has(item.attackId), false, item.attackId);
  const attempts = await observeAndRun(APP, safeFetch([]));
  for (const attempt of attempts.filter(item => item.result === 'blocked')) {
    assert.match(attempt.observed, /^HTTP (401|403|404|405|503)$/u, `${attempt.attackId}: ${attempt.observed}`);
  }
  const rules = await observeRules(APP, { fetch: safeFetch([]) });
  assert.equal(rules.length, RULE_CHECKS.length);
  assert.equal(rules.some(row => ['blocked', 'breached'].includes(row.result)), false);
});

test('404(경로 없음)·5xx 와 보내지 않은 점검은 막음으로 세지 않고 not_run 이며, 원본 표 직접 조회는 보내지 않는다', async () => {
  const attempts = await observeAndRun(APP, safeFetch([]));
  const byId = Object.fromEntries(attempts.map(attempt => [attempt.attackId, attempt]));
  assert.equal(byId['s05-direct-table'].result, 'not_run');
  assert.equal(byId['s05-direct-table'].observed, 'not_run');
  const missing = async (url, init) => { if (init?.alephEvidence) return new Response('not found', { status: 404 }); return new Response('{}'); };
  for (const attempt of await observeAndRun(APP, missing)) assert.notEqual(attempt.result, 'blocked', attempt.attackId);
  const broken = async () => new Response('err', { status: 503 });
  for (const attempt of await observeAndRun(APP, broken)) assert.equal(attempt.result, 'not_run', attempt.attackId);
});

test('로그인·변경 요청이 필요한 공격은 로그인 없이 보내 401 을 받아도 막음으로 세지 않고 보내지 않은 채 not_run 으로 둔다', async () => {
  const calls = [];
  const attempts = await observeAndRun(APP, safeFetch(calls));
  const byId = Object.fromEntries(attempts.map(attempt => [attempt.attackId, attempt]));
  for (const id of ['s04-query-identity', 's04-header-identity', 's05-direct-table', 's10-restore-unauth', 's12-out-of-zone', 's12-other-user-read']) {
    assert.equal(byId[id].result, 'not_run', id);
    assert.equal(byId[id].observed, 'not_run', id);
    assert.equal(calls.some(({ init }) => init.alephEvidence.caseId === id), false, `${id} 는 요청을 보내지 않는다`);
  }
  assert.deepEqual(attempts.filter(attempt => attempt.result === 'blocked').map(attempt => attempt.attackId).sort(), ['s03-fake-token', 's03-unauth-list', 's12-unauth-list']);
});
