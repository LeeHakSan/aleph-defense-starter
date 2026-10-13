import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { readAlerts, mask, extractAlert } from '../xdr/exfiltration/read-alerts.mjs';
import { buildDenyRules, checkDestination } from '../xdr/exfiltration/respond.mjs';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const fixture = JSON.parse(await read('xdr/fixtures/exfiltration.json'));
const num = (id) => Number(id.slice(3));

const make = ({ description, level, mitre = ['T1048'], bytes = '0', files, count, dstip = '203.0.113.99' }) => ({
  id: 't', timestamp: '2026-09-27T09:00:00+09:00', agent: { name: 'choi-bujang-pc' },
  rule: { level, description, mitre }, data: { srcip: '192.0.2.99', srcuser: 'user01', dstip, bytes, ...(files ? { files } : {}), ...(count ? { count } : {}) },
});

test('decide.mjs 는 아무것도 불러오지 않고 파일·바깥을 쓰지 않는다', async () => {
  const code = (await read('xdr/exfiltration/decide.mjs')).replace(/\/\/.*$/gmu, '');
  assert.doesNotMatch(code, /^\s*import\s|\brequire\s*\(|\bimport\s*\(|\bprocess\.|node:|readFile|writeFile|fetch\(|XMLHttpRequest|Date\.now|Math\.random/mu);
});

test('명확한 공격은 block, 애매한 건 alert, 정상 이벤트는 record 로 나뉜다', async () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const out = await decide(alert);
    assert.ok(['block', 'alert', 'record'].includes(out.action));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
    assert.ok(out.reason.length > 0);
    counts[out.action] += 1;
    const n = num(alert.id);
    if (n <= 10) assert.equal(out.action, 'block', `${alert.id} 명확한 공격`);
    else if (n <= 20) assert.equal(out.action, 'alert', `${alert.id} 애매한 시도`);
    else assert.equal(out.action, 'record', `${alert.id} 정상 이벤트`);
  }
  assert.deepEqual(counts, { block: 10, alert: 10, record: 10 });
});

test('확신도 경계: 0.85 이상 block, 0.5 이상 alert, 그 아래 record', async () => {
  for (const alert of fixture.alerts) {
    const out = await decide(alert);
    if (out.action === 'block') assert.ok(out.confidence >= 0.85, alert.id);
    if (out.action === 'alert') assert.ok(out.confidence >= 0.5 && out.confidence < 0.85, alert.id);
    if (out.action === 'record') assert.ok(out.confidence < 0.5, alert.id);
  }
});

test('큰 전송이 이상 징후와 함께 있을 때만 block 이다', async () => {
  // 큰 전송 + 처음 보는 목적지: block
  assert.equal((await decide(make({ description: '처음 보는 목적지로 자료가 나갔습니다.', level: 11, bytes: '90000000' }))).action, 'block');
  // 큰 전송 + 업무 시간 밖: block (파일 수가 아니라 용량으로도 판단)
  assert.equal((await decide(make({ description: '업무 시간 밖에 전송이 있었습니다.', level: 10, bytes: '60000000' }))).action, 'block');
  // 파일이 많은 전송(50건 이상) + 처음 보는 목적지: block
  assert.equal((await decide(make({ description: '처음 보는 목적지로 나갔습니다.', level: 10, bytes: '1000000', files: '80' }))).action, 'block');
  // 큰 전송이지만 이상 징후 없음: alert (평소 백업일 수 있음)
  assert.equal((await decide(make({ description: '큰 전송이 있었습니다.', level: 8, bytes: '90000000' }))).action, 'alert');
  // 이상 징후는 있지만 큰 전송이 아님: alert
  assert.equal((await decide(make({ description: '처음 보는 주소로 작은 파일이 나갔습니다.', level: 6, bytes: '400000' }))).action, 'alert');
  assert.equal((await decide(make({ description: '업무 시간 밖에 작은 전송이 있었습니다.', level: 9, bytes: '9000' }))).action, 'alert');
  // 경보 수준이 높아도 전송이 작으면 막지 않는다 (용량이 큰 전송일 때만 막는다)
  assert.equal((await decide(make({ description: '처음 보는 주소로 작은 파일이 나갔습니다.', level: 12, bytes: '400000' }))).action, 'alert');
  assert.equal((await decide(make({ description: '업무 시간 밖에 같은 목적지로 전송이 15번입니다.', level: 12, bytes: '90000', count: '15' }))).action, 'alert');
  // 압축 파일을 만들기만 했거나 전송이 실패한 경우는 막지 않는다
  assert.notEqual((await decide(make({ description: '수업 시간에 압축 파일 1건을 만들었습니다. 외부 전송은 아직 없습니다.', level: 12, bytes: '90000000' }))).action, 'block');
  assert.notEqual((await decide(make({ description: '전송이 실패 1건으로 끝났습니다. 목적지는 처음 봅니다.', level: 12, bytes: '90000000' }))).action, 'block');
  // 표지만 있는 작은 평소 전송: record, 표지 없는 평소 이벤트: record
  assert.equal((await decide(make({ description: '수업 자료 주소로 작은 동기화가 끝났습니다.', level: 3, bytes: '20000' }))).action, 'record');
  assert.equal((await decide(make({ description: '내 메모를 읽었습니다.', level: 3, mitre: [], bytes: '2400', dstip: '192.0.2.10' }))).action, 'record');
  // 반복 횟수가 많으면 확신도가 더 높다
  const once = await decide(make({ description: '처음 보는 목적지로 큰 전송이 있었습니다.', level: 10, bytes: '90000000' }));
  const repeated = await decide(make({ description: '처음 보는 목적지로 큰 전송이 있었습니다.', level: 10, bytes: '90000000', count: '5' }));
  assert.ok(repeated.confidence > once.confidence);
  assert.match(repeated.reason, /repeat_transfer/u);
});

test('이상한 입력도 오류 없이 record 로 답한다', async () => {
  for (const bad of [null, undefined, {}, 5, 'x', [], { rule: null }, { rule: { level: 'x', description: 7, mitre: 'T1048' }, data: { bytes: {}, files: [], count: 'abc' } }, { data: { bytes: '-9999999999' } }]) {
    const out = await decide(bad);
    assert.equal(out.action, 'record', JSON.stringify(bad));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
  }
});

test('패턴 목록: 패턴마다 이름·조건·근거 한 줄이 있고 decide.mjs 의 기준값과 같다', async () => {
  const patterns = JSON.parse(await read('xdr/exfiltration/patterns.json'));
  assert.equal(patterns.moduleKey, 'exfiltration');
  assert.match(patterns.source, /T1041/u);
  assert.match(patterns.source, /T1048/u);
  const names = patterns.patterns.map((item) => item.name);
  assert.equal(new Set(names).size, names.length);
  for (const item of patterns.patterns) {
    assert.ok(item.name && item.condition && item.basis, item.name);
    assert.doesNotMatch(item.basis, /\n/u);
    assert.match(item.basis, /T1041|T1048/u, `${item.name}: 근거에 기법 번호가 있어야 함`);
  }
  const code = await read('xdr/exfiltration/decide.mjs');
  for (const name of names) assert.ok(code.includes(name), `decide.mjs 에 ${name} 이 옮겨져 있어야 함`);
  assert.match(code, new RegExp(`const LARGE_BYTES = ${patterns.largeBytes};`, 'u'));
  assert.match(code, new RegExp(`const BULK_FILES = ${patterns.bulkFiles};`, 'u'));
  assert.match(code, new RegExp(`const MIN_REPEATS = ${patterns.minRepeats};`, 'u'));
});

test('경보 읽기: 건수와 뽑은 줄이 같고 원본을 고치지 않으며 비밀값처럼 보이는 값은 가린다', async () => {
  const before = await read('xdr/fixtures/exfiltration.json');
  const { total, rows } = await readAlerts();
  assert.equal(total, 30);
  assert.equal(rows.length, total);
  assert.equal(await read('xdr/fixtures/exfiltration.json'), before);
  for (const row of rows) assert.deepEqual(Object.keys(row), ['timestamp', 'srcip', 'srcuser', 'level', 'description']);
  assert.equal(mask('password=abc123 Bearer abcdefghijklmnop'), '[가림] [가림]');
});

test('차단 규칙: 막을 후보의 목적지만 만료 시각·근거 경보 번호와 함께 넣고, 평소 목적지·애매한 건의 목적지는 막지 않는다', async () => {
  const entries = [];
  for (const alert of fixture.alerts) entries.push({ alert, row: extractAlert(alert), decision: await decide(alert) });
  const rules = buildDenyRules(entries);
  assert.equal(rules.length, 8);
  for (const rule of rules) {
    assert.equal(rule.decision, 'deny');
    assert.ok(rule.dstip);
    assert.ok(rule.alertIds.length >= 1);
    assert.ok(Date.parse(rule.expiresAt) > 0);
  }
  // 다시 흘리기: 명확한 공격의 목적지는 막히고, 정상·애매한 이벤트의 목적지는 판정기 규칙으로 넘어간다.
  for (const { alert, decision } of entries) {
    const hit = checkDestination(rules, alert.data.dstip, alert.timestamp);
    if (decision.action === 'block') assert.equal(hit?.decision, 'deny', alert.id);
    else assert.equal(hit, null, alert.id);
  }
  // 평소 목적지(수업 자료실)는 절대 막히지 않는다.
  for (const usual of ['192.0.2.10', '198.51.100.10']) assert.equal(checkDestination(rules, usual, '2026-09-27T09:30:00+09:00'), null);
  // 만료 뒤에는 걸리지 않는다.
  assert.equal(checkDestination(rules, '203.0.113.50', '2026-09-28T00:00:00+09:00'), null);
});
