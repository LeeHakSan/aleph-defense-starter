// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'resource_zones',
  'route_not_allowed',
  'write_not_allowed',
]);

// 구역 규칙(8단계): 엔진이 확인한 service·method·route·실제 path 가 아래 읽기 구역과 정확히 맞을 때만 연다.
// 자기 메모 목록은 모호한 GET /api/notes 대신 명시적인 GET /api/my/notes 로만 열고, 메모 한 건 읽기는 정확한 :id 경로만 연다.
// 계약에는 자료 소유자·강사 역할이 없으므로 판정기는 쓰기(추가·수정·삭제, 공지 수정 포함)를 열지 않는다.
// 개별 메모의 소유자와 강사 권한은 자료 API 가 검증된 로그인과 저장된 값으로 다시 확인한다. subjectId 는 owner_id 와 비교하지 않는다.
// 강사 공지 경로, 그 밖의 경로, 자료 ID 자리의 기능 이름(export 등), 쿼리가 붙은 요청은 거부한다.
const READ_ZONES = Object.freeze({
  'GET /api/my/notes': /^\/api\/my\/notes$/u,
  'GET /api/notes/:id': /^\/api\/notes\/([A-Za-z0-9_-]{1,64})$/u,
  'GET /notes/:id': /^\/notes\/([A-Za-z0-9_-]{1,64})$/u,
});
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const FUNCTION_NAMES = new Set(['export', 'import', 'all', 'list', 'search', 'download', 'upload', 'bulk', 'backup', 'restore', 'admin', 'new']);

// 가상 접속 사건은 엔진이 source 를 'judge_fixture' 로 표시해 넘긴 것만 읽습니다.
// 'none'(실제 경로)이거나 값이 비었거나 형식이 틀리면 근거로 쓰지 않고, 정상값으로 채우지도 않습니다.
const FIXTURE_SOURCE = 'judge_fixture';
const STEP_UP_MAX_AGE_SECONDS = 900;
const BURST_WINDOW_SECONDS = 300;
const BURST_MIN_COUNT = 10;

function readSignals(request) {
  const signals = request.signals;
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) return null;
  if (signals.source !== FIXTURE_SOURCE) return null;
  if (typeof signals.region !== 'string' || typeof signals.network !== 'string') return null;
  if (!Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) return null;
  return signals;
}

function recentRiskCount(request) {
  if (!Array.isArray(request.recentEvents)) return 0;
  let total = 0;
  for (const event of request.recentEvents) {
    if (event && event.kind === 'risk_signal'
        && Number.isInteger(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= BURST_WINDOW_SECONDS
        && Number.isInteger(event.count) && event.count > 0) total += event.count;
  }
  return total;
}

// 평소와 다른 시각 + 처음 보는 네트워크 + 짧은 시간에 몰린 위험 사건이 모두 맞을 때만 복합 이상입니다.
// 지역(region)은 단독 근거로도, 차단 근거로도 쓰지 않습니다.
function isCompositeAnomaly(request) {
  const signals = readSignals(request);
  if (!signals) return false;
  const oddHour = signals.hour <= 5 || signals.hour >= 23;
  return oddHour && signals.network === 'unusual' && recentRiskCount(request) >= BURST_MIN_COUNT;
}

function zoneRule(request) {
  if (WRITE_METHODS.has(request.method)) return { deny: 'write_not_allowed', reasonCode: 'write_not_allowed' };
  const pattern = typeof request.route === 'string' && Object.hasOwn(READ_ZONES, request.route) ? READ_ZONES[request.route] : null;
  const match = pattern && request.service === 'notes' && request.route.startsWith(`${request.method} `)
    && typeof request.path === 'string' ? pattern.exec(request.path) : null;
  if (!match) return { deny: 'route_not_allowed', reasonCode: 'route_not_allowed' };
  if ((match[1] && FUNCTION_NAMES.has(match[1].toLowerCase())) || request.queryLength !== 0) {
    return { deny: 'resource_zones', reasonCode: 'route_not_allowed' };
  }
  return { allow: 'resource_zones' };
}

function stepUpDone(request) {
  const stepUp = request.stepUp;
  return Boolean(stepUp) && stepUp.verified === true
    && Number.isInteger(stepUp.authAgeSeconds)
    && stepUp.authAgeSeconds >= 0 && stepUp.authAgeSeconds <= STEP_UP_MAX_AGE_SECONDS;
}

const answer = (request, decision, reasonCode, ruleIds) => ({
  schema: 'aleph.decision.v1',
  requestId: request.requestId,
  decision,
  reasonCode,
  ruleIds,
});

export async function decide(request) {
  if (request.deviceRegistered !== true) {
    return answer(request, 'deny', 'device_not_registered', ['device_registered']);
  }

  const zone = zoneRule(request);
  if (zone.deny) return answer(request, 'deny', zone.reasonCode, [zone.deny]);

  if (isCompositeAnomaly(request)) {
    if (!stepUpDone(request)) return answer(request, 'step_up', 'step_up_required', ['step_up_required']);
    return answer(request, 'allow', 'approved', ['device_registered', zone.allow, 'step_up_required']);
  }

  return answer(request, 'allow', 'approved', ['device_registered', zone.allow]);
}
