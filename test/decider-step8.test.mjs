import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const ID = '3f2b8c1e-6a4d-4e0b-9c7a-1d2e3f4a5b6c';
const ask = async (method, route, path, patch = {}) => {
  const { normal } = fixtureRequests();
  const out = await decide({ ...normal, requestId: randomUUID(), method, route: `${method} ${route}`, path, ...patch });
  assert.ok(out.ruleIds.every(id => RULE_IDS.includes(id)), JSON.stringify(out.ruleIds));
  return out;
};

test('자기 메모 구역: 읽기·추가·수정·삭제 경로는 허용', async () => {
  for (const [method, route, path] of [['GET', '/notes', '/notes'], ['POST', '/notes', '/notes'],
    ['GET', '/notes/:id', `/notes/${ID}`], ['PUT', '/notes/:id', `/notes/${ID}`], ['DELETE', '/notes/:id', '/notes/demo']]) {
    const out = await ask(method, route, path);
    assert.equal(out.decision, 'allow', `${method} ${path}`);
    assert.deepEqual(out.ruleIds, ['device_registered', 'own_notes_zone']);
  }
});

test('강사 공지 구역: 읽기는 허용, 수정은 판정기에서 열지 않음', async () => {
  for (const [route, path] of [['/notices', '/notices'], ['/notices/:id', `/notices/${ID}`]]) {
    const out = await ask('GET', route, path);
    assert.equal(out.decision, 'allow');
    assert.deepEqual(out.ruleIds, ['device_registered', 'class_notices_read_zone']);
  }
  for (const [method, route, path] of [['PUT', '/notices/:id', `/notices/${ID}`], ['POST', '/notices', '/notices'],
    ['DELETE', '/notices/:id', `/notices/${ID}`]]) {
    const out = await ask(method, route, path);
    assert.equal(out.decision, 'deny', `${method} ${path}`);
    assert.equal(out.reasonCode, 'zone_not_allowed');
    assert.deepEqual(out.ruleIds, ['notice_write_instructor_only']);
  }
});

test('알 수 없는 경로·모양 불일치·기능 이름은 거부', async () => {
  const cases = [
    ['GET', '/notes/:id', '/notes/export'],
    ['GET', '/notes/:id', '/notes/export/all'],
    ['GET', '/notes/:id', '/notes/..'],
    ['GET', '/notes/:id', '/notes/%2e%2e'],
    ['GET', '/notes/:id', '/notes/'],
    ['GET', '/notes/:id', '/notices/abc'],
    ['GET', '/notes', '/notes/abc'],
    ['POST', '/notes/:id', `/notes/${ID}`],
    ['PUT', '/notes', '/notes'],
    ['DELETE', '/notes', '/notes'],
    ['GET', '/users', '/users'],
    ['GET', '/admin/notes', '/admin/notes'],
    ['GET', '/notes/:id/export', `/notes/${ID}/export`],
  ];
  for (const [method, route, path] of cases) {
    const out = await ask(method, route, path);
    assert.equal(out.decision, 'deny', `${method} ${path}`);
    assert.equal(out.reasonCode, 'zone_not_allowed');
    assert.deepEqual(out.ruleIds, ['unknown_route_deny']);
  }
});

test('method 와 route 가 서로 다르거나 형식이 틀리면 거부', async () => {
  const { normal } = fixtureRequests();
  for (const patch of [{ method: 'PUT' }, { method: 'get' }, { method: undefined }, { route: undefined }, { route: 'GET notes' },
    { path: undefined }, { path: 42 }, { route: 'GET /notes/:id?export=1' }]) {
    const out = await decide({ ...normal, requestId: randomUUID(), ...patch });
    assert.equal(out.decision, 'deny', JSON.stringify(patch));
  }
});

test('쿼리는 기능을 고르지 못하고 경로 판단은 그대로', async () => {
  const { normal } = fixtureRequests();
  const out = await decide({ ...normal, requestId: randomUUID(), queryLength: 12, querySha256: 'b'.repeat(64) });
  assert.equal(out.decision, 'allow');
});

test('이전 규칙 유지: 미등록 기기는 구역보다 먼저 거부, 복합 이상 사건은 추가 확인', async () => {
  const { normal, suspicious } = fixtureRequests();
  const off = await decide({ ...normal, requestId: randomUUID(), deviceRegistered: false, route: 'GET /users', path: '/users' });
  assert.equal(off.reasonCode, 'device_not_registered');
  assert.equal((await decide(suspicious)).decision, 'step_up');
  const checked = await decide({ ...suspicious, requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal(checked.decision, 'allow');
  assert.deepEqual(checked.ruleIds, ['device_registered', 'own_notes_zone', 'step_up_required']);
  const unknown = await decide({ ...suspicious, requestId: randomUUID(), route: 'GET /users', path: '/users' });
  assert.equal(unknown.decision, 'deny');
});

test('/api 접두사가 붙은 같은 모양도 같은 구역으로 본다', async () => {
  assert.equal((await ask('GET', '/api/notes/:id', `/api/notes/${ID}`)).decision, 'allow');
  assert.equal((await ask('PUT', '/api/notices/:id', `/api/notices/${ID}`)).decision, 'deny');
});
