import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { detect } from '../src/detect.mjs';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const OBSERVE = { action: 'observe' };
const propose = subject => ({ action: 'propose_revocation', reasonCode: 'burst_read', subject });

const reads = (count, { gap = 2000, sub = 'learner_fixture', start = START, method = 'GET' } = {}) => Array.from({ length: count }, (_, i) => ({
  at: new Date(start + i * gap).toISOString(), method, identity: { sub },
}));

test('120건은 관찰, 121건부터 회수 제안이고 응답에는 세 값만 있다', () => {
  assert.deepEqual(detect(reads(120)), OBSERVE);
  assert.deepEqual(detect(reads(121)), propose('learner_fixture'));
  assert.deepEqual(Object.keys(detect(reads(200))), ['action', 'reasonCode', 'subject']);
  assert.deepEqual(detect([]), OBSERVE);
});

test('10분 경계: 정확히 10분 안에 121건은 제안, 1초라도 넘으면 120건 묶음이라 관찰', () => {
  assert.deepEqual(detect(reads(121, { gap: 5000 })), propose('learner_fixture'));
  assert.deepEqual(detect(reads(121, { gap: 5000 }).map((event, i, all) => (i === all.length - 1
    ? { ...event, at: new Date(Date.parse(event.at) + 1000).toISOString() } : event))), OBSERVE);
  assert.deepEqual(detect(reads(200, { gap: 7000 })), OBSERVE);
});

test('어느 10분 구간에서든: 앞뒤로 흩어진 조회 가운데 몰린 구간이 있으면 제안', () => {
  const before = reads(50, { gap: 60000, start: START - 3 * 3600 * 1000 });
  const burst = reads(121, { gap: 1000 });
  const after = reads(50, { gap: 60000, start: START + 3 * 3600 * 1000 });
  assert.deepEqual(detect([...before, ...burst, ...after]), propose('learner_fixture'));
});

test('순서가 뒤섞여 들어와도 같은 결과', () => {
  const shuffled = reads(121).reverse();
  assert.deepEqual(detect(shuffled), propose('learner_fixture'));
  const interleaved = [...reads(100), ...reads(100, { sub: 'other_fixture' })].sort((a, b) => b.at.localeCompare(a.at));
  assert.deepEqual(detect(interleaved), OBSERVE);
});

test('사용자별로 따로 센다: 합치면 넘어도 각자 120건 이하면 관찰', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, { sub: 'other_fixture' })]), OBSERVE);
  assert.deepEqual(detect([...reads(120), ...reads(120, { sub: 'other_fixture' })]), OBSERVE);
  assert.deepEqual(detect([...reads(60), ...reads(130, { sub: 'other_fixture' })]), propose('other_fixture'));
});

test('GET 이 아닌 요청과 잘못된 사건은 세지 않는다', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, { method: 'POST' })]), OBSERVE);
  assert.deepEqual(detect(reads(200, { method: 'PUT' })), OBSERVE);
  assert.deepEqual(detect(reads(121, { method: 'get' })), propose('learner_fixture'));
  const broken = [null, undefined, 7, 'x', [], {}, { at: 'nope', method: 'GET', identity: { sub: 'learner_fixture' } },
    { at: START, method: 'GET', identity: {} }, { at: START, method: 'GET', identity: { sub: '' } },
    { at: START, method: 'GET', identity: { sub: 42 } }, { at: START, method: 'GET', userId: 'learner_fixture' },
    { at: START, method: 'GET', identity: null }, { at: START, identity: { sub: 'learner_fixture' } }];
  assert.deepEqual(detect([...reads(120), ...broken]), OBSERVE);
  assert.deepEqual(detect([...reads(121), ...broken]), propose('learner_fixture'));
});

test('브라우저가 보낸 사용자 번호가 아니라 identity.sub 만 신원으로 읽는다', () => {
  const forged = reads(200).map(event => ({ ...event, userId: 'victim', sub: 'victim', identity: { sub: 'learner_fixture' } }));
  assert.deepEqual(detect(forged), propose('learner_fixture'));
});

test('여러 사용자가 넘으면 먼저 넘은 한 명만 제안', () => {
  const late = reads(150, { sub: 'late_fixture', start: START + 3600 * 1000 });
  const early = reads(130, { sub: 'early_fixture' });
  assert.deepEqual(detect([...late, ...early]), propose('early_fixture'));
  assert.deepEqual(detect([...early, ...late]), propose('early_fixture'));
});

test('입력을 바꾸지 않고, 배열이 아니면 오류', () => {
  const events = reads(121).reverse();
  const copy = JSON.stringify(events);
  detect(events);
  assert.equal(JSON.stringify(events), copy);
  for (const bad of [undefined, null, 'x', 7, {}]) assert.throws(() => detect(bad), TypeError);
});

test('detect.mjs 는 아무것도 불러오지 않고 파일·네트워크·환경을 쓰지 않는다', async () => {
  const source = await readFile(new URL('../src/detect.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source.replace(/\/\/.*$/gmu, ''), /\bimport\b|\brequire\b|\bfetch\b|process\.|node:/u);
});
