import assert from 'node:assert/strict';
import { readdir, readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import deviceHandler from '../api/device/[action].js';
import { createProtectedAccess, protectedAccess } from '../src/protected-access.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const root = fileURLToPath(new URL('..', import.meta.url));
const read = path => readFile(join(root, path), 'utf8');
const LOGIN = { kind: 'student', userId: '11111111-1111-4111-8111-111111111111' };

function fakeResponse() {
  return {
    headers: {}, code: null, body: null,
    setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
  };
}
const callDevice = async (action, method, extra = {}) => {
  const response = fakeResponse();
  await deviceHandler({ method, query: { action }, ...extra }, response);
  return response;
};

test('승인 확인: 어댑터가 없으면 로그인한 요청도 503 으로 막고, 승인을 알려 줘야만 연다', async () => {
  assert.deepEqual(await protectedAccess.check(LOGIN), { ok: false, status: 503, error: 'device_verification_unavailable' });
  const ok = createProtectedAccess({ adapter: async () => 'approved' });
  assert.deepEqual(await ok.check(LOGIN), { ok: true });
  for (const verdict of ['denied', 'pending']) {
    const gate = createProtectedAccess({ adapter: async () => verdict });
    assert.deepEqual(await gate.check(LOGIN), { ok: false, status: 403, error: 'device_not_approved' });
  }
});

test('승인 확인: 알 수 없는 답·오류·예외·승인처럼 보이는 값·함수가 아닌 어댑터는 모두 막는다', async () => {
  const adapters = [async () => true, async () => 'ok', async () => 'APPROVED', async () => ({ approved: true }), async () => undefined,
    async () => { throw new Error('연결 끊김'); }, 'approved', {}, 7];
  for (const adapter of adapters) {
    const result = await createProtectedAccess({ adapter }).check(LOGIN);
    assert.deepEqual(result, { ok: false, status: 503, error: 'device_verification_unavailable' }, String(adapter));
  }
});

test('승인 확인은 브라우저가 보낸 값을 읽지 않는다: 확인 함수는 로그인 결과만 받는다', async () => {
  const seen = [];
  const gate = createProtectedAccess({ adapter: async (info, login) => { seen.push({ info, login }); return 'denied'; } });
  await gate.check(LOGIN, { headers: { 'x-device-approved': 'true' }, query: { approved: '1' }, body: { approved: true, role: 'instructor' } });
  assert.deepEqual(seen, [{ info: { purpose: 'request' }, login: LOGIN }]);
  assert.equal(protectedAccess.check.length, 1);
  const noAdapter = await protectedAccess.check({ ...LOGIN, approved: true, deviceRegistered: true, role: 'instructor' });
  assert.equal(noAdapter.status, 503);
});

test('승인 상태·승인 요청 경로: 어댑터가 없으면 승인도 접수도 하지 않는다', async () => {
  const status = await callDevice('status', 'GET', { headers: { 'x-device-approved': 'true' }, query: { action: 'status', approved: '1' } });
  assert.equal(status.code, 200);
  assert.deepEqual(status.body, { schema: 'aleph.device-status.v1', connected: false, approved: false, approval: 'unavailable', reasonCode: 'device_verification_unavailable' });
  assert.equal(status.headers['cache-control'], 'no-store');
  const approval = await callDevice('approval', 'POST', { body: { approved: true, deviceKey: 'x' } });
  assert.equal(approval.code, 503);
  assert.deepEqual(approval.body, { error: 'device_verification_unavailable', approval: 'unavailable', approved: false });
  assert.equal((await callDevice('status', 'POST')).code, 405);
  assert.equal((await callDevice('approval', 'GET')).code, 405);
  assert.equal((await callDevice('other', 'GET')).code, 404);
});

test('승인 상태·요청: 어댑터가 알려 준 결과만 반영한다', async () => {
  const mk = verdict => createProtectedAccess({ adapter: async () => verdict });
  assert.deepEqual(await mk('approved').status(), { schema: 'aleph.device-status.v1', connected: true, approved: true, approval: 'approved', reasonCode: 'approved' });
  assert.equal((await mk('pending').status()).approved, false);
  assert.equal((await mk('denied').status()).approval, 'denied');
  assert.equal((await mk('approved').requestApproval()).http, 200);
  assert.equal((await mk('pending').requestApproval()).http, 202);
  assert.equal((await mk('pending').requestApproval()).body.approved, false);
  assert.equal((await mk('denied').requestApproval()).http, 403);
  assert.equal((await mk(null).requestApproval()).http, 503);
});

test('모든 보호 자료 API 는 로그인 확인 함수를 거치고, 그 함수가 승인 확인을 부른다', async () => {
  const guarded = ['api/notes.js', 'api/notes/[id].js', 'api/my/notes.js', 'api/notices/index.js', 'api/notices/[id].js', 'api/restore/[noteId].js'];
  for (const file of guarded) assert.match(await read(file), /await authenticate\(request, response\)/u, file);
  const common = await read('src/notes-common.mjs');
  const login = common.indexOf('await verifyLogin(');
  const gate = common.indexOf('await protectedAccess.check(login)');
  assert.ok(login > 0 && gate > login, '로그인 확인 다음에 승인 확인');
  const open = ['api/recovery-plan/index.js', 'api/device/[action].js', 'api/auth/[action].js', 'api/ai.js', 'api/threat-intel.js'];
  for (const file of open) assert.doesNotMatch(await read(file), /authenticate\(/u, file);
});

const STORAGE = /localStorage|sessionStorage|indexedDB|document\.cookie|\bcaches\b|serviceWorker/u;

test('첫 화면(/): manifest 연결·앱 이름·승인 상태 표시가 있고, 로그인 폼·메모 목록·메모 요청·저장소 사용이 없다', async () => {
  const html = await read('public/index.html');
  assert.match(html, /<link[^>]+rel="manifest"[^>]+href="\/manifest\.webmanifest"/u);
  assert.match(html, /<title>[^<]*자료실[^<]*<\/title>/u);
  assert.match(html, /기기 승인 상태/u);
  assert.match(html, /\/api\/device\/status/u);
  assert.match(html, /\/api\/device\/approval/u);
  assert.match(html, /오프라인/u);
  assert.match(html, /설치했다는 표시/u);
  assert.doesNotMatch(html, /type=["']?password/iu);
  assert.doesNotMatch(html, /id=["']notes["']/u);
  assert.doesNotMatch(html, /\/api\/notes|\/api\/auth|\/api\/restore|\/api\/notices|\/api\/my\//u);
  assert.doesNotMatch(html, STORAGE);
  assert.doesNotMatch(html, /<form/iu);
});

test('첫 화면: 자료실 열기는 서버가 approved·connected 를 모두 true 로 알려 줄 때만 켜진다', async () => {
  const html = await read('public/index.html');
  assert.match(html, /data\?\.connected === true && data\?\.approved === true/u);
  assert.match(html, /aria-disabled="true">자료실 열기/u);
  assert.doesNotMatch(html, /<a[^>]+id="open-link"[^>]+href=/u);
  assert.equal((html.match(/openLink\.href = /gu) ?? []).length, 1);
  const approvedBranch = html.slice(html.indexOf('if (approved) {'), html.indexOf('} else {', html.indexOf('if (approved) {')));
  assert.match(approvedBranch, /openLink\.href = '\/vault\.html'/u);
});

test('자료실 화면(/vault.html): 승인 전에는 로그인 폼·메모 목록·메모 요청이 없고, 자료실 코드는 승인 확인 뒤에만 불러온다', async () => {
  const html = await read('public/vault.html');
  assert.doesNotMatch(html, /type=["']?password/iu);
  assert.doesNotMatch(html, /id=["']notes["']/u);
  assert.doesNotMatch(html, /\/api\/notes|\/api\/auth/u);
  assert.doesNotMatch(html, STORAGE);
  assert.match(html, /\/api\/device\/status/u);
  const importAt = html.indexOf("import('/vault-app.js')");
  assert.ok(importAt > 0);
  assert.equal((html.match(/import\('\/vault-app\.js'\)/gu) ?? []).length, 1);
  const before = html.slice(html.lastIndexOf('const approved = await serverApproved();'), importAt);
  assert.match(before, /if \(!approved\) \{[\s\S]*?return false;/u);
  assert.match(html, /response\.ok && data\?\.connected === true && data\?\.approved === true/u);
});

test('자료실 화면 코드(vault-app.js): 토큰을 브라우저 저장소에 넣지 않고, 요청마다 승인을 다시 확인하며, 중지하면 모두 비운다', async () => {
  const js = await read('public/vault-app.js');
  assert.doesNotMatch(js.replace(/\/\/.*$/gmu, ''), STORAGE);
  assert.match(js, /await isApproved\(\)/u);
  assert.match(js, /stop\(\) \{[\s\S]*session = null;[\s\S]*notes = \[\];[\s\S]*root\.replaceChildren\(\)/u);
  assert.doesNotMatch(js, /Authorization:\s*`Bearer \$\{(?!token)/u);
});

test('설치형 웹앱 설정(manifest): 이름·시작 주소·범위·표시 방식·아이콘이 있고 아이콘 파일이 있다', async () => {
  const manifest = JSON.parse(await read('public/manifest.webmanifest'));
  assert.equal(typeof manifest.name, 'string');
  assert.ok(manifest.name.includes('자료실'));
  assert.equal(manifest.short_name.length > 0, true);
  assert.equal(manifest.start_url, '/');
  assert.equal(manifest.scope, '/');
  assert.equal(manifest.display, 'standalone');
  assert.match(manifest.background_color, /^#[0-9a-f]{6}$/iu);
  assert.ok(Array.isArray(manifest.icons) && manifest.icons.length >= 1);
  for (const icon of manifest.icons) {
    assert.ok(icon.src.startsWith('/'));
    assert.ok((await stat(join(root, 'public', icon.src))).size > 0);
  }
  assert.match(manifest.description, /설치 표시만으로는 기기를 믿지 않습니다/u);
  assert.doesNotMatch(JSON.stringify(manifest), /token|secret|key/iu);
});

test('공개 파일에 비밀값·메모 본문·시드 표식이 없다', async () => {
  const files = (await readdir(join(root, 'public'))).filter(name => name !== 'aleph.json');
  for (const name of files) {
    const text = await read(`public/${name}`);
    assert.doesNotMatch(text, /eyJ[A-Za-z0-9_-]{12,}\.|sb_secret_|sb_publishable_[A-Za-z0-9]{8}|SUPABASE_SECRET_KEY|service_role/u, name);
    assert.equal(text.includes(config.sampleMarker), false, name);
    assert.doesNotMatch(text, /실습용 가상/u, name);
  }
});

test('설정: 11단계이고 기존 복구 경로·허용 경로는 그대로다', () => {
  assert.equal(config.step, 11);
  assert.equal(config.restoreRoute, '/api/restore/:noteId');
  assert.deepEqual(config.allowedRoutes, ['GET /api/my/notes', 'GET /api/notes/:id', 'GET /notes/:id']);
});
