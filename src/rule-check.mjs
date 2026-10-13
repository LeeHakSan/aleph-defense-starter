import { createHash, randomUUID } from 'node:crypto';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { ENGINE } from './sources.mjs';
import { loadRecoveryPlan } from './policy-files.mjs';

// 고정된 가상 입력으로만 판정기·탐지 규칙을 실행한다. 사용자가 보낸 값은 사례 이름(고정 목록과 비교)뿐이고 코드로 실행하지 않는다.
// 실제 세션·메모·기기 상태는 읽거나 바꾸지 않는다. ready 는 "가상 조건에서 기대한 결과가 나왔다"는 뜻이며 실제 기기의 승인 상태가 아니다.
// 응답의 source 는 학생 작업, engine 은 제공 엔진이다. 엔진이 그 판정을 실제 요청에서 집행했는지는 이 저장소에서 확인하지 못하므로 engineEnforced 는 not_run 이다.
const SOURCE_DECIDER = '학생 판정기(src/decider.mjs)';
const SOURCE_DETECT = '학생 탐지 규칙(src/detect.mjs)';
const EMPTY_QUERY_SHA256 = createHash('sha256').update('').digest('hex');

function request(overrides = {}) {
  return {
    schema: 'aleph.decision.v1', requestId: randomUUID(), classId: 'class_check', projectId: 'project_check', subjectId: 'learner_check',
    deviceId: 'c'.repeat(16), service: 'notes', method: 'GET', path: '/api/notes/check', route: 'GET /api/notes/:id',
    queryLength: 0, querySha256: EMPTY_QUERY_SHA256, at: new Date().toISOString(), policyRevision: 1, deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [], signals: { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
    ...overrides,
  };
}

export const RULE_CASES = Object.freeze({
  's06-unregistered': [() => request({ deviceRegistered: false }), 'deny'],
  's07-compound': [() => request({ signals: { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 },
    recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] }), 'step_up'],
  's08-unknown-route': [() => request({ route: 'GET /__unknown__', path: '/__unknown__' }), 'deny'],
  's08-all-notes': [() => request({ route: 'GET /api/notes', path: '/api/notes' }), 'deny'],
  's08-write-notice': [() => request({ method: 'POST', route: 'POST /api/notices', path: '/api/notices' }), 'deny'],
});

export async function runRuleCheck(caseId) {
  if (typeof caseId !== 'string') return null;
  if (Object.hasOwn(RULE_CASES, caseId)) {
    const [build, expected] = RULE_CASES[caseId];
    const result = await decide(build());
    return { ready: result.decision === expected, decision: result.decision, reasonCode: result.reasonCode, ruleIds: result.ruleIds,
      source: SOURCE_DECIDER, engine: ENGINE, engineEnforced: 'not_run' };
  }
  if (caseId === 's09-burst-read') {
    const start = Date.now();
    const events = Array.from({ length: 121 }, (_, i) => ({ at: new Date(start + i * 2000).toISOString(), method: 'GET', identity: { sub: 'check_user' } }));
    const result = detect(events);
    return { ready: result.action === 'propose_revocation', action: result.action, reasonCode: result.reasonCode ?? null,
      source: SOURCE_DETECT, engine: ENGINE, engineEnforced: 'not_run' };
  }
  if (caseId === 's10-policy-verified') {
    try {
      const { plan } = await loadRecoveryPlan();
      return { ready: plan.verified === true, restoreVersion: plan.restoreVersion, source: '학생 안전 정책 사본(backups/safe-policy.json)', engine: ENGINE, engineEnforced: 'not_run' };
    } catch {
      return { ready: false, restoreVersion: null, source: '학생 안전 정책 사본(backups/safe-policy.json)', engine: ENGINE, engineEnforced: 'not_run' };
    }
  }
  return null;
}

// 작전실 화면용: 탐지 연습 사건(가상)을 실행한 결과. 실제 사건이 아니라 local_fixture 이다.
export function detectionSummary() {
  const start = Date.UTC(2026, 9, 1);
  const reads = (count) => Array.from({ length: count }, (_, i) => ({ at: new Date(start + i * 2000).toISOString(), method: 'GET', identity: { sub: 'fixture_user' } }));
  return {
    source: 'local_fixture',
    cases: [
      { name: '10분 안에 120건', events: 120, action: detect(reads(120)).action },
      { name: '10분 안에 121건', events: 121, action: detect(reads(121)).action },
    ],
  };
}
