import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decide } from '../xdr/privilege/decide.mjs';
import { readAlerts, mask, extractAlert } from '../xdr/privilege/read-alerts.mjs';
import { buildDenyRules, checkSession } from '../xdr/privilege/respond.mjs';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const fixture = JSON.parse(await read('xdr/fixtures/privilege.json'));
const num = (id) => Number(id.slice(3));

const make = ({ description, level, mitre = ['T1078'], count, srcip = '203.0.113.50', srcuser = 'user01' }) => ({
  id: 't', timestamp: '2026-09-27T09:00:00+09:00', agent: { name: 'choi-bujang-pc' },
  rule: { level, description, mitre }, data: { srcip, srcuser, ...(count ? { count } : {}) },
});

test('decide.mjs 는 아무것도 불러오지 않고 파일·바깥을 쓰지 않는다', async () => {
  const code = (await read('xdr/privilege/decide.mjs')).replace(/\/\/.*$/gmu, '');
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
    if (n <= 9) assert.equal(out.action, 'block', `${alert.id} 명확한 공격`);
    else if (n <= 17) assert.equal(out.action, 'alert', `${alert.id} 애매한 시도`);
    else assert.equal(out.action, 'record', `${alert.id} 정상 이벤트`);
  }
  assert.deepEqual(counts, { block: 9, alert: 8, record: 9 });
});

test('확신도 경계: 0.85 이상 block, 0.5 이상 alert, 그 아래 record', async () => {
  for (const alert of fixture.alerts) {
    const out = await decide(alert);
    if (out.action === 'block') assert.ok(out.confidence >= 0.85, alert.id);
    if (out.action === 'alert') assert.ok(out.confidence >= 0.5 && out.confidence < 0.85, alert.id);
    if (out.action === 'record') assert.ok(out.confidence < 0.5, alert.id);
  }
});

test('관리자 권한 상승·사용 근거가 있고 수준이 높을 때만 block 이다', async () => {
  // 관리자 그룹 추가 + 높은 수준: block
  assert.equal((await decide(make({ description: 'user09 가 관리자 그룹에 추가됐습니다.', level: 12 }))).action, 'block');
  // 낯선 주소에서 관리자 명령: block
  assert.equal((await decide(make({ description: '처음 보는 주소에서 관리자 명령을 실행했습니다.', level: 11, mitre: ['T1068'] }))).action, 'block');
  // 수준이 낮고 신호 하나뿐: alert
  assert.equal((await decide(make({ description: 'user09 가 관리자 그룹에 추가됐습니다.', level: 7 }))).action, 'alert');
  // 신호가 둘 겹치면 수준이 낮아도 block
  assert.equal((await decide(make({ description: '관리자 그룹에 추가되고 곧바로 권한 명령을 실행했습니다.', level: 8 }))).action, 'block');
  // 관리자 그룹이 아닌 그룹 변경: alert
  assert.equal((await decide(make({ description: 'user02 가 과제 그룹에 추가됐습니다. 관리자 그룹은 아닙니다.', level: 10 }))).action, 'alert');
  assert.equal((await decide(make({ description: '관리자 그룹은 아니며 user02 가 과제 그룹에 추가됐습니다.', level: 10 }))).action, 'alert');
  // 평소 주소의 관리자 명령 한 번, 실패한 명령, 취소된 상승: alert
  assert.equal((await decide(make({ description: '평소 주소에서 관리자 명령이 한 번 실행됐습니다.', level: 5, mitre: ['T1068'] }))).action, 'alert');
  assert.equal((await decide(make({ description: '관리자 명령이 실패 1건으로 끝났습니다.', level: 7, mitre: ['T1068'] }))).action, 'alert');
  assert.equal((await decide(make({ description: '권한 상승 창이 한 번 뜨고 취소됐습니다.', level: 6, mitre: ['T1068'] }))).action, 'alert');
  // 표지만 있고 근거 없음: alert, 표지 없는 평소 이벤트: record
  assert.equal((await decide(make({ description: '자기 계정 종류를 조회했습니다.', level: 6 }))).action, 'alert');
  assert.equal((await decide(make({ description: '수업용 관리 계정 admin01 이 평소 주소에서 로그인했습니다.', level: 3, mitre: [] }))).action, 'record');
  // 같은 계정이 3개 이상 한꺼번에 올라가면 확신도가 더 높다
  const one = await decide(make({ description: '같은 주소에서 계정이 관리자 그룹에 추가됐습니다.', level: 10 }));
  const many = await decide(make({ description: '같은 주소에서 계정이 관리자 그룹에 추가됐습니다.', level: 10, count: '4' }));
  assert.ok(many.confidence > one.confidence);
  assert.match(many.reason, /multi_account_admin_add/u);
});

test('이상한 입력도 오류 없이 record 로 답한다', async () => {
  for (const bad of [null, undefined, {}, 5, 'x', [], { rule: null }, { rule: { level: 'x', description: 7, mitre: 'T1078' }, data: { count: {} } }]) {
    const out = await decide(bad);
    assert.equal(out.action, 'record', JSON.stringify(bad));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
  }
});

test('패턴 목록: 패턴마다 이름·조건·근거 한 줄이 있고 decide.mjs 에 옮겨 적혀 있다', async () => {
  const patterns = JSON.parse(await read('xdr/privilege/patterns.json'));
  assert.equal(patterns.moduleKey, 'privilege');
  assert.match(patterns.source, /T1068/u);
  assert.match(patterns.source, /T1078/u);
  const names = patterns.patterns.map((item) => item.name);
  assert.equal(new Set(names).size, names.length);
  for (const item of patterns.patterns) {
    assert.ok(item.name && item.condition && item.basis, item.name);
    assert.doesNotMatch(item.basis, /\n/u);
    assert.match(item.basis, /T1068|T1078/u, `${item.name}: 근거에 기법 번호가 있어야 함`);
  }
  const code = await read('xdr/privilege/decide.mjs');
  for (const name of names) assert.ok(code.includes(name), `decide.mjs 에 ${name} 이 옮겨져 있어야 함`);
  assert.equal(patterns.minRepeats, 3);
  assert.match(code, /const MIN_REPEATS = 3;/u);
});

test('경보 읽기: 건수와 뽑은 줄이 같고 원본을 고치지 않으며 비밀값처럼 보이는 값은 가린다', async () => {
  const before = await read('xdr/fixtures/privilege.json');
  const { total, rows } = await readAlerts();
  assert.equal(total, 26);
  assert.equal(rows.length, total);
  assert.equal(await read('xdr/fixtures/privilege.json'), before);
  for (const row of rows) assert.deepEqual(Object.keys(row), ['timestamp', 'srcip', 'srcuser', 'level', 'description']);
  assert.equal(mask('password=abc123 Bearer abcdefghijklmnop'), '[가림] [가림]');
});

test('차단 규칙: 막을 후보의 세션(주소+계정)만 만료 시각·근거 경보 번호와 함께 넣고, 같은 계정의 평소 세션·애매한 건은 막지 않는다', async () => {
  const entries = [];
  for (const alert of fixture.alerts) entries.push({ alert, row: extractAlert(alert), decision: await decide(alert) });
  const rules = buildDenyRules(entries);
  assert.equal(rules.length, 8);
  for (const rule of rules) {
    assert.equal(rule.decision, 'deny');
    assert.ok(rule.srcuser);
    assert.ok(rule.alertIds.length >= 1);
    assert.ok(Date.parse(rule.expiresAt) > 0);
  }
  // 다시 흘리기: 명확한 공격 세션은 막히고, 같은 계정의 정상·애매한 세션은 판정기 규칙으로 넘어간다.
  for (const { alert, row, decision } of entries) {
    const hit = checkSession(rules, row.srcip, row.srcuser, alert.timestamp);
    if (decision.action === 'block') assert.equal(hit?.decision, 'deny', alert.id);
    else assert.equal(hit, null, alert.id);
  }
  // user01 은 공격(203.0.113.11)과 정상 로그인(192.0.2.76)이 모두 있다: 공격 세션만 막힌다.
  assert.equal(checkSession(rules, '203.0.113.11', 'user01', '2026-09-27T09:30:00+09:00')?.decision, 'deny');
  assert.equal(checkSession(rules, '192.0.2.76', 'user01', '2026-09-27T09:30:00+09:00'), null);
  // 만료 뒤에는 걸리지 않는다.
  assert.equal(checkSession(rules, '203.0.113.11', 'user01', '2026-09-28T00:00:00+09:00'), null);
});
