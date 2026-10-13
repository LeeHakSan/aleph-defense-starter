import assert from 'node:assert/strict';
import { test } from 'node:test';
import { noteAccess, noticeAccess, resourceId } from '../src/access.mjs';
import { handleNote } from '../src/notes-item.mjs';
import { handleNotice, isInstructor, listNotices } from '../src/notices.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const A_NOTE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const NO_OWNER = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const NOTICE = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const MISSING = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

function fakeDb(tables, { failOn } = {}) {
  return {
    from(name) {
      const state = { op: 'select', filters: [], patch: null, limit: null };
      const run = () => {
        if (failOn === name) return { data: null, error: { code: 'fake' } };
        const rows = tables[name];
        let hit = rows.filter(row => state.filters.every(([key, value]) => row[key] === value));
        if (state.op === 'update') hit.forEach(row => Object.assign(row, state.patch));
        if (state.op === 'delete') hit.forEach(row => rows.splice(rows.indexOf(row), 1));
        if (state.limit !== null) hit = hit.slice(0, state.limit);
        return { data: hit.map(row => ({ ...row })), error: null };
      };
      const query = {
        select: () => query,
        order: () => query,
        eq: (key, value) => { state.filters.push([key, value]); return query; },
        limit: (count) => { state.limit = count; return query; },
        update: (patch) => { state.op = 'update'; state.patch = patch; return query; },
        delete: () => { state.op = 'delete'; return query; },
        then: (resolve, reject) => Promise.resolve(run()).then(resolve, reject),
      };
      return query;
    },
  };
}

function fakeResponse() {
  return {
    headers: {}, code: null, body: null,
    setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

const world = () => ({
  notes: [
    { id: A_NOTE, owner_id: A, title: 'A의 가상 메모', content: 'A 전용 가상 내용' },
    { id: NO_OWNER, owner_id: null, title: '주인 없는 가상 메모', content: '가상' },
  ],
  notices: [{ id: NOTICE, title: '가상 공지', content: '가상 공지 내용', created_at: 1, updated_at: 1 }],
  instructors: [],
});
const student = (userId, tables, opts) => ({ kind: 'student', userId, db: fakeDb(tables, opts) });
const call = async (handler, session, method, id, body) => {
  const response = fakeResponse();
  await handler(session, { method, query: { id }, body }, response);
  return response;
};

test('자원 ID는 메모와 공지를 서로 다른 이름으로 구별한다', () => {
  assert.equal(resourceId('note', A_NOTE), `note:${A_NOTE}`);
  assert.equal(resourceId('notice', NOTICE), `notice:${NOTICE}`);
  assert.equal(resourceId('note'), 'note:*');
  assert.notEqual(resourceId('note', NOTICE), resourceId('notice', NOTICE));
});

test('구역 판단: 소유자만 메모, 강사만 공지 수정', () => {
  assert.equal(noteAccess({ userId: A, ownerId: A }).allowed, true);
  assert.equal(noteAccess({ userId: A, ownerId: A.toUpperCase() }).allowed, true);
  assert.deepEqual(noteAccess({ userId: B, ownerId: A }), { allowed: false, reason: 'not_owner' });
  assert.equal(noteAccess({ userId: A, ownerId: null }).allowed, false);
  assert.equal(noteAccess({ userId: A, ownerId: undefined }).allowed, false);
  assert.equal(noticeAccess({ method: 'GET', isInstructor: false }).allowed, true);
  assert.equal(noticeAccess({ method: 'PUT', isInstructor: true }).allowed, true);
  assert.deepEqual(noticeAccess({ method: 'PUT', isInstructor: false }), { allowed: false, reason: 'not_instructor' });
  assert.equal(noticeAccess({ method: 'PUT', isInstructor: 'true' }).allowed, false);
  assert.equal(noticeAccess({ method: 'DELETE', isInstructor: true }).allowed, false);
});

test('메모: A 는 자기 메모를 읽고 고치고, 응답에 자원 ID 가 실린다', async () => {
  const tables = world();
  const read = await call(handleNote, student(A, tables), 'GET', A_NOTE);
  assert.equal(read.code, 200);
  assert.equal(read.headers['x-resource-id'], `note:${A_NOTE}`);
  const put = await call(handleNote, student(A, tables), 'PUT', A_NOTE, { title: '바꿈', role: 'instructor' });
  assert.equal(put.code, 200);
  assert.equal(tables.notes[0].title, '바꿈');
  assert.equal(Object.hasOwn(tables.notes[0], 'role'), false);
});

test('메모: B 가 A 의 메모를 읽기·수정·삭제하면 403 이고 내용이 나오지 않으며 그대로 남는다', async () => {
  const tables = world();
  const before = JSON.stringify(tables.notes);
  for (const [method, body] of [['GET'], ['PUT', { title: '가로챔' }], ['PUT', { title: 'x', owner_id: B, role: 'instructor' }], ['DELETE']]) {
    const response = await call(handleNote, student(B, tables), method, A_NOTE, body);
    assert.equal(response.code, 403, method);
    assert.deepEqual(response.body, { error: 'FORBIDDEN', reason: 'not_owner' });
    assert.equal(JSON.stringify(response.body).includes('A 전용'), false);
  }
  assert.equal(JSON.stringify(tables.notes), before);
});

test('메모: 주인 없는 메모와 소유자 바꾸기는 거부, 형식 오류·없는 id 는 따로 응답', async () => {
  const tables = world();
  assert.equal((await call(handleNote, student(A, tables), 'GET', NO_OWNER)).code, 403);
  const swap = await call(handleNote, student(A, tables), 'PUT', A_NOTE, { title: 'x', owner_id: B });
  assert.equal(swap.code, 403);
  assert.equal(swap.body.reason, 'owner_change');
  assert.equal(tables.notes[0].owner_id, A);
  assert.equal((await call(handleNote, student(A, tables), 'GET', 'export')).code, 400);
  assert.equal((await call(handleNote, student(A, tables), 'GET', MISSING)).code, 404);
  assert.equal((await call(handleNote, student(A, tables), 'POST', A_NOTE)).code, 405);
});

test('공지: 로그인한 학생은 목록과 한 건을 읽는다', async () => {
  const tables = world();
  const list = fakeResponse();
  await listNotices(student(B, tables), list);
  assert.equal(list.code, 200);
  assert.equal(list.headers['x-resource-id'], 'notice:*');
  assert.deepEqual(list.body.map(({ id, title }) => ({ id, title })), [{ id: NOTICE, title: '가상 공지' }]);
  const one = await call(handleNotice, student(B, tables), 'GET', NOTICE);
  assert.equal(one.code, 200);
  assert.equal(one.headers['x-resource-id'], `notice:${NOTICE}`);
  assert.equal((await call(handleNotice, student(B, tables), 'GET', MISSING)).code, 404);
});

test('공지: 일반 학생의 수정은 본문의 role 이 무엇이든 403 이고 공지는 그대로다', async () => {
  const tables = world();
  const before = JSON.stringify(tables.notices);
  for (const body of [{ title: '바꿈' }, { title: '바꿈', role: 'instructor' }, { title: '바꿈', isInstructor: true, owner_id: B }]) {
    const response = await call(handleNotice, student(B, tables), 'PUT', NOTICE, body);
    assert.equal(response.code, 403);
    assert.deepEqual(response.body, { error: 'FORBIDDEN', reason: 'not_instructor' });
  }
  assert.equal(JSON.stringify(tables.notices), before);
  // 없는 공지도 권한이 없으면 403 으로 답해 공지가 있는지 알려 주지 않는다.
  assert.equal((await call(handleNotice, student(B, tables), 'PUT', MISSING, { title: 'x' })).code, 403);
});

test('공지: 저장된 강사만 수정하고, 심판 접속은 강사 표에 있어도 강사가 아니다', async () => {
  const tables = world();
  tables.instructors.push({ user_id: A });
  const ok = await call(handleNotice, student(A, tables), 'PUT', NOTICE, { title: '새 제목', body: '새 내용' });
  assert.equal(ok.code, 200);
  assert.deepEqual({ title: tables.notices[0].title, content: tables.notices[0].content }, { title: '새 제목', content: '새 내용' });
  assert.notEqual(tables.notices[0].updated_at, 1);
  assert.equal(await isInstructor({ kind: 'judge', userId: A, db: fakeDb(tables) }), false);
  assert.equal((await call(handleNotice, { kind: 'judge', userId: A, db: fakeDb(tables) }, 'PUT', NOTICE, { title: 'x' })).code, 403);
  assert.equal((await call(handleNotice, student(A, tables), 'PUT', NOTICE, { title: '' })).code, 400);
  assert.equal((await call(handleNotice, student(A, tables), 'PUT', MISSING, { title: 'x' })).code, 404);
});

test('공지: 권한 조회가 실패하면 수정하지 않고 502, 지원하지 않는 동작은 405', async () => {
  const tables = world();
  const before = JSON.stringify(tables.notices);
  const down = await call(handleNotice, student(A, tables, { failOn: 'instructors' }), 'PUT', NOTICE, { title: 'x' });
  assert.equal(down.code, 502);
  assert.equal(JSON.stringify(tables.notices), before);
  for (const method of ['POST', 'DELETE', 'PATCH']) {
    assert.equal((await call(handleNotice, student(A, tables), method, NOTICE)).code, 405, method);
  }
  assert.equal((await call(handleNotice, student(A, tables), 'GET', 'export')).code, 400);
});
