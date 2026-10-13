import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const fresh = (request, patch = {}) => ({ ...request, requestId: randomUUID(), ...patch });
const RISK = [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }];

test('정상 사건은 허용, 복합 이상 사건은 추가 확인입니다', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.equal((await decide(normal)).decision, 'allow');
  const out = await decide(suspicious);
  assert.equal(out.decision, 'step_up');
  assert.equal(out.reasonCode, 'step_up_required');
  assert.deepEqual(out.ruleIds, ['step_up_required']);
  assert.ok(out.ruleIds.every(id => RULE_IDS.includes(id)));
});

test('다시 확인한 복합 이상 사건은 허용, 오래됐거나 형식이 틀린 확인은 다시 추가 확인입니다', async () => {
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(fresh(suspicious, { stepUp: { verified: true, authAgeSeconds: 60 } }))).decision, 'allow');
  for (const stepUp of [{ verified: true, authAgeSeconds: 901 }, { verified: true, authAgeSeconds: null },
    { verified: 'true', authAgeSeconds: 10 }, { verified: false, authAgeSeconds: null }, undefined]) {
    assert.equal((await decide(fresh(suspicious, { stepUp }))).decision, 'step_up');
  }
});

test('지역만 낯설다고 막거나 추가 확인하지 않습니다', async () => {
  const { normal } = fixtureRequests();
  const out = await decide(fresh(normal, { signals: { source: 'judge_fixture', region: 'foreign', network: 'usual', hour: 14 } }));
  assert.equal(out.decision, 'allow');
});

test('세 조건 가운데 하나라도 빠지면 추가 확인하지 않습니다', async () => {
  const { suspicious } = fixtureRequests();
  const base = suspicious.signals;
  assert.equal((await decide(fresh(suspicious, { signals: { ...base, hour: 14 } }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { signals: { ...base, network: 'usual' } }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { recentEvents: [] }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 3 }] }))).decision, 'allow');
  assert.equal((await decide(fresh(suspicious, { recentEvents: [{ kind: 'risk_signal', ageSeconds: 9000, count: 20 }] }))).decision, 'allow');
});

test('출처가 judge_fixture 가 아니거나 값이 없으면 근거로 쓰지 않고 정상값으로 채우지도 않습니다', async () => {
  const { suspicious } = fixtureRequests();
  const odd = { region: 'foreign', network: 'unusual', hour: 3 };
  for (const signals of [{ source: 'none', ...odd }, { source: 'client_header', ...odd }, { ...odd },
    { source: 'judge_fixture', region: 'foreign', network: 'unusual' }, { source: 'judge_fixture', ...odd, hour: '3' },
    { source: 'judge_fixture', ...odd, hour: 24 }, null, undefined, 'judge_fixture', []]) {
    const out = await decide(fresh(suspicious, { signals }));
    assert.equal(out.decision, 'allow', JSON.stringify(signals));
    assert.deepEqual(out.ruleIds, ['device_registered']);
  }
});

test('요청 밖의 위조 값은 읽지 않습니다', async () => {
  const { normal } = fixtureRequests();
  const forged = fresh(normal, { headers: { 'x-forwarded-for': '203.0.113.9' }, geo: { region: 'foreign' }, role: 'admin',
    device: { registered: false }, clientSignals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 } });
  assert.equal((await decide(forged)).decision, 'allow');
});

test('기기 규칙은 그대로이고 미등록 기기는 먼저 거부합니다', async () => {
  const { suspicious } = fixtureRequests();
  for (const deviceRegistered of [false, undefined, 'true', 1]) {
    const out = await decide(fresh(suspicious, { deviceRegistered }));
    assert.equal(out.decision, 'deny');
    assert.equal(out.reasonCode, 'device_not_registered');
  }
});
