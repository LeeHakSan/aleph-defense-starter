import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decide } from '../xdr/persistence/decide.mjs';
import { readAlerts, mask, extractAlert } from '../xdr/persistence/read-alerts.mjs';
import { buildDenyRules, checkSource } from '../xdr/persistence/respond.mjs';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const fixture = JSON.parse(await read('xdr/fixtures/persistence.json'));
const num = (id) => Number(id.slice(3));
const isNormal = (alert) => num(alert.id) >= 17;

const make = ({ description, level, mitre = ['T1543'], path, count, srcip = '203.0.113.50' }) => ({
  id: 't', timestamp: '2026-09-27T09:00:00+09:00', agent: { name: 'choi-bujang-pc' },
  rule: { level, description, mitre }, data: { srcip, srcuser: 'user01', ...(path ? { path } : {}), ...(count ? { count } : {}) },
});
const TEMP = 'C:\\Users\\user01\\AppData\\Local\\Temp\\x.exe';

test('decide.mjs 는 아무것도 불러오지 않고 파일·바깥을 쓰지 않는다', async () => {
  const code = (await read('xdr/persistence/decide.mjs')).replace(/\/\/.*$/gmu, '');
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
    if (n <= 8) assert.equal(out.action, 'block', `${alert.id} 명확한 공격`);
    else if (n <= 16) assert.equal(out.action, 'alert', `${alert.id} 애매한 시도`);
    else assert.equal(out.action, 'record', `${alert.id} 정상 이벤트`);
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
});

test('확신도 경계: 0.85 이상 block, 0.5 이상 alert, 그 아래 record', async () => {
  for (const alert of fixture.alerts) {
    const out = await decide(alert);
    if (out.action === 'block') assert.ok(out.confidence >= 0.85, alert.id);
    if (out.action === 'alert') assert.ok(out.confidence >= 0.5 && out.confidence < 0.85, alert.id);
    if (out.action === 'record') assert.ok(out.confidence < 0.5, alert.id);
  }
});

test('지속 장치가 실제로 등록된 근거가 있고 수준이 높을 때만 block 이다', async () => {
  // 서명 없는 새 서비스 + 높은 수준: block
  assert.equal((await decide(make({ description: '서명 없는 새 서비스가 등록됐습니다.', level: 12, path: TEMP }))).action, 'block');
  // 처음 보는 예약 작업 + 높은 수준: block
  assert.equal((await decide(make({ description: '처음 보는 예약 작업이 있습니다.', level: 11, mitre: ['T1053'] }))).action, 'block');
  // 등록 근거는 있지만 수준이 낮고 신호 하나뿐: alert
  assert.equal((await decide(make({ description: '처음 보는 예약 작업이 있습니다.', level: 7, mitre: ['T1053'] }))).action, 'alert');
  // 등록 근거가 둘 겹치면 수준이 낮아도 block
  assert.equal((await decide(make({ description: '평소 목록에 없는 서비스가 다시 켜도 남도록 등록됐습니다.', level: 8 }))).action, 'block');
  // 임시 폴더에 파일만 있고 등록은 없음: alert
  assert.equal((await decide(make({ description: '임시 폴더에 실행 파일이 하나 생겼습니다. 서비스 등록은 없습니다.', level: 8, path: TEMP }))).action, 'alert');
  // 서명을 모를 뿐: alert
  assert.equal((await decide(make({ description: '시작 항목이 하나 있습니다. 서명은 아직 모릅니다.', level: 7 }))).action, 'alert');
  // 기법 표지만 있고 근거 없음: alert, 낮은 수준의 평소 동작: record
  assert.equal((await decide(make({ description: '서비스 설명만 바뀌었습니다.', level: 5 }))).action, 'alert');
  assert.equal((await decide(make({ description: '서명된 기존 서비스가 실행 중입니다.', level: 3 }))).action, 'record');
  assert.equal((await decide(make({ description: '로그인했습니다.', level: 3, mitre: [] }))).action, 'record');
  // 서명 없는 서비스 등록이 3건 이상 반복되면 확신도가 더 높다
  const single = await decide(make({ description: '원격 주소에서 서명 없는 서비스 등록이 있습니다.', level: 12 }));
  const repeated = await decide(make({ description: '원격 주소에서 서명 없는 서비스 등록이 있습니다.', level: 12, count: '3' }));
  assert.ok(repeated.confidence > single.confidence);
  assert.match(repeated.reason, /repeat_registration/u);
});

test('높은 수준이어도 등록이 없었다는 경보는 막지 않는다', async () => {
  const out = await decide(make({ description: '시작 폴더 변경이 1건입니다. 이어서 실행된 기록은 없습니다.', level: 10, path: TEMP }));
  assert.notEqual(out.action, 'block');
});

test('이상한 입력도 오류 없이 record 로 답한다', async () => {
  for (const bad of [null, undefined, {}, 5, 'x', [], { rule: null }, { rule: { level: 'x', description: 7, mitre: 'T1543' }, data: { path: 3, count: {} } }]) {
    const out = await decide(bad);
    assert.equal(out.action, 'record', JSON.stringify(bad));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
  }
});

test('패턴 목록: 패턴마다 이름·조건·근거 한 줄이 있고 decide.mjs 에 옮겨 적혀 있다', async () => {
  const patterns = JSON.parse(await read('xdr/persistence/patterns.json'));
  assert.equal(patterns.moduleKey, 'persistence');
  assert.match(patterns.source, /T1543/u);
  assert.match(patterns.source, /T1053/u);
  const names = patterns.patterns.map((item) => item.name);
  assert.equal(new Set(names).size, names.length);
  for (const item of patterns.patterns) {
    assert.ok(item.name && item.condition && item.basis, item.name);
    assert.doesNotMatch(item.basis, /\n/u);
    assert.match(item.basis, /T1543|T1053|T1547/u, `${item.name}: 근거에 기법 번호가 있어야 함`);
  }
  const code = await read('xdr/persistence/decide.mjs');
  for (const name of names) assert.ok(code.includes(name), `decide.mjs 에 ${name} 이 옮겨져 있어야 함`);
  assert.equal(patterns.minRepeats, 3);
  assert.match(code, /const MIN_REPEATS = 3;/u);
});

test('경보 읽기: 건수와 뽑은 줄이 같고 원본을 고치지 않으며 비밀값처럼 보이는 값은 가린다', async () => {
  const before = await read('xdr/fixtures/persistence.json');
  const { total, rows } = await readAlerts();
  assert.equal(total, 24);
  assert.equal(rows.length, total);
  assert.equal(await read('xdr/fixtures/persistence.json'), before);
  for (const row of rows) assert.deepEqual(Object.keys(row), ['timestamp', 'srcip', 'srcuser', 'level', 'description']);
  assert.equal(mask('password=abc123 Bearer abcdefghijklmnop'), '[가림] [가림]');
});

test('차단 규칙: 막을 후보만 출발 주소별로 만료 시각·근거 경보 번호와 함께 넣고, 애매한 건·정상 주소는 넣지 않는다', async () => {
  const entries = [];
  for (const alert of fixture.alerts) entries.push({ alert, row: extractAlert(alert), decision: await decide(alert) });
  const rules = buildDenyRules(entries);
  assert.equal(rules.length, 7);
  for (const rule of rules) {
    assert.equal(rule.decision, 'deny');
    assert.ok(rule.alertIds.length >= 1);
    assert.ok(Date.parse(rule.expiresAt) > 0);
  }
  const keepOut = new Set(entries.filter(({ decision }) => decision.action !== 'block').map(({ row }) => row.srcip));
  assert.equal(rules.some((rule) => keepOut.has(rule.srcip)), false);
  for (const { alert, row, decision } of entries) {
    const hit = checkSource(rules, row.srcip, alert.timestamp);
    if (decision.action === 'block') assert.equal(hit?.decision, 'deny', alert.id);
    else assert.equal(hit, null, alert.id);
  }
  assert.equal(checkSource(rules, '203.0.113.12', '2026-09-28T00:00:00+09:00'), null);
});
