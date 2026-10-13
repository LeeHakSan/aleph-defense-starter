import { RULE_IDS } from './decider.mjs';
import { observeAll, observeRules, observeScreens } from './attack-check.mjs';
import { detectionSummary } from './rule-check.mjs';
import { loadRecoveryPlan } from './policy-files.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import matrix from '../data/attack-matrix.json' with { type: 'json' };

// 작전실 화면이 읽는 실제 관측. 이 배포에 지금 요청을 보내 얻은 응답 상태·요청 ID·확인 시각만 담고, 화면의 문구는 통과 근거가 아니다.
// 메모 제목·본문·토큰·실명·기기 키는 읽지도 담지도 않는다. 확인하지 못한 것은 not_run·null 로 남긴다.
const MIN_INTERVAL_MS = 15000;
let last = null;
let running = null;

const count = (rows, result) => rows.filter((row) => row.result === result).length;

async function recoverySummary() {
  try {
    const { plan } = await loadRecoveryPlan();
    return { policyCopy: { verified: true, restoreVersion: plan.restoreVersion, currentVersion: plan.currentVersion, changes: plan.changes.length, source: 'recovery_plan' } };
  } catch (error) {
    return { policyCopy: { verified: false, error: error?.code ?? 'unknown', source: 'recovery_plan' } };
  }
}

async function observe() {
  const checkedAt = new Date().toISOString();
  // 묶음(npm run bundle)과 같은 함수·같은 점검 목록으로 관측해서 수치가 어긋나지 않게 한다. 화면·정책 확인은 점검 수치에 넣지 않고 따로 둔다.
  const rows = await observeAll(config.publicAppUrl);
  const screens = await observeScreens(config.publicAppUrl);
  const rules = await observeRules(config.publicAppUrl);
  const recovery = await recoverySummary();
  const planned = matrix.attacks;
  const executed = planned.filter((item) => item.status === 'executed').length;
  return {
    schema: 'aleph.operations.v1',
    checkedAt,
    commit: process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 12) ?? null,
    step: config.step,
    summary: { total: rows.length, blocked: count(rows, 'blocked'), breached: count(rows, 'breached'), notRun: count(rows, 'not_run') },
    rows,
    screens,
    judgeRules: {
      ruleIds: [...RULE_IDS],
      note: '서버가 고정된 가상 입력으로 규칙을 실행한 결과다. 실제 공격 실행이 아니라서 점검 수치에 넣지 않는다.',
      cases: rules.map(({ attackId, result, observed, requests }) => ({ attackId, result, observed, requestId: requests[0]?.requestId ?? null })),
    },
    detection: detectionSummary(),
    revocation: { connected: false, state: 'not_connected', note: '회수는 반 엔진이 집행하며 이 저장소에는 회수 연결이 없다. 수치는 null 이다.', revoked: null, elapsedSeconds: null },
    recovery: { ...recovery, memoBackups: { state: 'not_run', note: '메모 사본 개수는 로그인·기기 승인이 필요한 정보라 읽지 않았다.' } },
    attackMatrix: {
      total: planned.length, executed, notRun: planned.length - executed, source: 'data/attack-matrix.json',
      items: planned.map(({ no, name, region, stage, attack, status, relatedCases, note }) => ({ no, name, region, stage, attack, status, relatedCases, note })),
    },
  };
}

// 짧은 간격 안의 반복 호출은 직전 관측을 그대로 돌려준다(자기 확인 시각 포함). 관측이 실패하면 이전 성공 값을 쓰지 않고 실패를 알린다.
export async function operationsStatus({ now = Date.now() } = {}) {
  if (last && now - last.at < MIN_INTERVAL_MS) return { ...last.value, cached: true };
  running ??= observe().then((value) => { last = { at: Date.now(), value }; return value; }).finally(() => { running = null; });
  try {
    return { ...(await running), cached: false };
  } catch {
    last = null;
    return { schema: 'aleph.operations.v1', error: 'observation_failed', checkedAt: new Date().toISOString(), rows: [], summary: null, cached: false };
  }
}
