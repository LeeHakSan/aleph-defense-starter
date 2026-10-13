import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const ID = '3f2b8c1e-6a4d-4e0b-9c7a-1d2e3f4a5b6c';
const OTHER = { subjectId: 'other_fixture', deviceId: 'b'.repeat(16) };
const ask = async (method, route, path, patch = {}) => {
  const { normal } = fixtureRequests();
  const out = await decide({ ...normal, requestId: randomUUID(), method, route: `${method} ${route}`, path, ...patch });
  assert.ok(out.ruleIds.every(id => RULE_IDS.includes(id)), JSON.stringify(out.ruleIds));
  return out;
};

test('정확한 읽기 구역만 허용: 자기 목록(/api/my/notes)과 메모 한 건 읽기', async () => {
  for (const [route, path, patch] of [['/api/my/notes', '/api/my/notes'], ['/api/notes/:id', `/api/notes/${ID}`],
    ['/notes/:id', '/notes/demo'], ['/api/notes/:id', `/api/notes/${ID}`, OTHER]]) {
    const out = await ask('GET', route, path, patch);
    assert.equal(out.decision, 'allow', path);
    assert.equal(out.reasonCode, 'approved');
    assert.deepEqual(out.ruleIds, ['device_registered', 'resource_zones']);
  }
});

test('모든 쓰기(메모 추가·수정·삭제, 공지 수정)는 소유·강사 증거가 없어 거부', async () => {
  for (const [method, route, path] of [['POST', '/api/notes', '/api/notes'], ['PUT', '/api/notes/:id', `/api/notes/${ID}`],
    ['PATCH', '/api/notes/:id', `/api/notes/${ID}`], ['DELETE', '/api/notes/:id', `/api/notes/${ID}`],
    ['PUT', '/api/notices/:id', `/api/notices/${ID}`], ['PUT', '/notes/:id', '/notes/demo'], ['POST', '/api/my/notes', '/api/my/notes']]) {
    const out = await ask(method, route, path);
    assert.equal(out.decision, 'deny', `${method} ${path}`);
    assert.equal(out.reasonCode, 'write_not_allowed');
    assert.deepEqual(out.ruleIds, ['write_not_allowed']);
  }
});

test('모호한 목록·다른 구역·알 수 없는 경로는 거부', async () => {
  for (const [route, path] of [['/api/notes', '/api/notes'], ['/notes', '/notes'], ['/api/notices', '/api/notices'],
    ['/api/notices/:id', `/api/notices/${ID}`], ['/notices/:id', '/notices/demo'], ['/api/users', '/api/users'],
    ['/api/admin/notes', '/api/admin/notes'], ['/api/notes/:id/export', `/api/notes/${ID}/export`]]) {
    const out = await ask('GET', route, path);
    assert.equal(out.decision, 'deny', path);
    assert.equal(out.reasonCode, 'route_not_allowed');
    assert.deepEqual(out.ruleIds, ['route_not_allowed']);
  }
});

test('route 와 path·method·service 가 맞지 않으면 거부', async () => {
  const cases = [
    ['GET', '/api/notes/:id', '/api/notes/'],
    ['GET', '/api/notes/:id', `/api/notes/${ID}/x`],
    ['GET', '/api/notes/:id', '/api/notes/..'],
    ['GET', '/api/notes/:id', '/api/notes/%2e%2e'],
    ['GET', '/api/notes/:id', `/api/notices/${ID}`],
    ['GET', '/api/my/notes', '/api/my/notes/'],
    ['GET', '/api/my/notes', '/api/notes'],
  ];
  for (const [method, route, path] of cases) {
    assert.equal((await ask(method, route, path)).decision, 'deny', path);
  }
  const { normal } = fixtureRequests();
  for (const patch of [{ method: 'PUT' }, { method: 'get' }, { method: undefined }, { route: undefined }, { route: 'GET notes' },
    { path: undefined }, { path: 42 }, { route: 'GET /notes/:id?export=1' }, { service: 'notices' }, { service: undefined }]) {
    assert.equal((await decide({ ...normal, requestId: randomUUID(), ...patch })).decision, 'deny', JSON.stringify(patch));
  }
});

test('자료 ID 자리의 기능 이름과 쿼리 기능 선택은 거부', async () => {
  for (const name of ['export', 'EXPORT', 'all', 'admin', 'backup', 'restore', 'upload']) {
    const out = await ask('GET', '/api/notes/:id', `/api/notes/${name}`);
    assert.equal(out.decision, 'deny', name);
    assert.equal(out.reasonCode, 'route_not_allowed');
    assert.deepEqual(out.ruleIds, ['resource_zones']);
  }
  for (const patch of [{ queryLength: 12 }, { queryLength: 1 }, { queryLength: undefined }]) {
    assert.equal((await ask('GET', '/api/my/notes', '/api/my/notes', patch)).decision, 'deny', JSON.stringify(patch));
  }
});

test('이전 규칙 유지: 미등록 기기는 먼저 거부, 복합 이상 사건은 추가 확인', async () => {
  const { normal, suspicious } = fixtureRequests();
  const off = await decide({ ...normal, requestId: randomUUID(), deviceRegistered: false });
  assert.equal(off.reasonCode, 'device_not_registered');
  const offWrite = await decide({ ...normal, requestId: randomUUID(), deviceRegistered: false, method: 'PUT', route: 'PUT /notes/:id' });
  assert.equal(offWrite.reasonCode, 'device_not_registered');
  assert.equal((await decide(suspicious)).decision, 'step_up');
  const checked = await decide({ ...suspicious, requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal(checked.decision, 'allow');
  assert.deepEqual(checked.ruleIds, ['device_registered', 'resource_zones', 'step_up_required']);
  const suspiciousWrite = await decide({ ...suspicious, requestId: randomUUID(), method: 'PUT', route: 'PUT /notes/:id' });
  assert.equal(suspiciousWrite.decision, 'deny');
});
