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

test('A(자료실 주인)는 자기 기기로 자기 메모를 어떤 메모 id 로든 읽고 고친다', async () => {
  for (const [method, route, path, patch] of [['GET', '/notes', '/notes'], ['POST', '/notes', '/notes'],
    ['GET', '/notes/:id', '/notes/demo'], ['GET', '/notes/:id', `/notes/${ID}`], ['PUT', '/notes/:id', `/notes/${ID}`],
    ['DELETE', '/notes/:id', '/notes/demo'], ['GET', '/api/notes/:id', '/api/notes/demo']]) {
    const out = await ask(method, route, path, patch);
    assert.equal(out.decision, 'allow', `${method} ${path}`);
    assert.deepEqual(out.ruleIds, ['device_registered', 'own_notes_zone']);
  }
});

test('B 가 A 의 메모를 읽기·고치기·지우기, 목록·추가하면 거부', async () => {
  for (const [method, route, path] of [['GET', '/notes/:id', '/notes/demo'], ['GET', '/notes/:id', `/notes/${ID}`],
    ['PUT', '/notes/:id', '/notes/demo'], ['DELETE', '/notes/:id', '/notes/demo'], ['GET', '/notes', '/notes'],
    ['POST', '/notes', '/notes'], ['GET', '/api/notes/:id', '/api/notes/demo']]) {
    const out = await ask(method, route, path, OTHER);
    assert.equal(out.decision, 'deny', `${method} ${path}`);
    assert.equal(out.reasonCode, 'zone_not_allowed');
    assert.deepEqual(out.ruleIds, ['own_notes_zone']);
  }
  for (const subjectId of [undefined, '', 'LEARNER_FIXTURE', 'learner_fixture ', 42]) {
    assert.equal((await ask('GET', '/notes/:id', '/notes/demo', { subjectId })).decision, 'deny', String(subjectId));
  }
});

test('A 의 계정이라도 다른 기기·다른 반·다른 프로젝트에서 오면 자기 메모 구역이 아니다', async () => {
  for (const patch of [{ deviceId: 'c'.repeat(16) }, { deviceId: undefined }, { classId: 'class_other' }, { projectId: 'project_other' }]) {
    const out = await ask('GET', '/notes/:id', '/notes/demo', patch);
    assert.equal(out.decision, 'deny', JSON.stringify(patch));
    assert.deepEqual(out.ruleIds, ['own_notes_zone']);
  }
});

test('강사 공지: 읽기는 허용, 일반 학생의 수정·추가·삭제는 거부', async () => {
  for (const [route, path, patch] of [['/notices', '/notices'], ['/notices/:id', `/notices/${ID}`], ['/notices/:id', '/notices/demo', OTHER]]) {
    const out = await ask('GET', route, path, patch);
    assert.equal(out.decision, 'allow');
    assert.deepEqual(out.ruleIds, ['device_registered', 'class_notices_read_zone']);
  }
  for (const [method, route, path, patch] of [['PUT', '/notices/:id', `/notices/${ID}`], ['PUT', '/notices/:id', '/notices/demo', OTHER],
    ['POST', '/notices', '/notices'], ['DELETE', '/notices/:id', `/notices/${ID}`], ['PUT', '/api/notices/:id', `/api/notices/${ID}`]]) {
    const out = await ask(method, route, path, patch);
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

test('쿼리가 붙으면 정확한 경로가 아니므로 자기 메모라도 거부', async () => {
  for (const patch of [{ queryLength: 12 }, { queryLength: 1 }, { queryLength: undefined }]) {
    const out = await ask('GET', '/notes/:id', '/notes/demo', patch);
    assert.equal(out.decision, 'deny', JSON.stringify(patch));
    assert.deepEqual(out.ruleIds, ['unknown_route_deny']);
  }
});

test('이전 규칙 유지: 미등록 기기는 구역보다 먼저 거부, 복합 이상 사건은 추가 확인', async () => {
  const { normal, suspicious } = fixtureRequests();
  const off = await decide({ ...normal, requestId: randomUUID(), deviceRegistered: false, route: 'GET /users', path: '/users' });
  assert.equal(off.reasonCode, 'device_not_registered');
  assert.equal((await decide(suspicious)).decision, 'step_up');
  const checked = await decide({ ...suspicious, requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } });
  assert.equal(checked.decision, 'allow');
  assert.deepEqual(checked.ruleIds, ['device_registered', 'own_notes_zone', 'step_up_required']);
  const otherSuspicious = await decide({ ...suspicious, requestId: randomUUID(), ...OTHER });
  assert.equal(otherSuspicious.decision, 'deny');
});
