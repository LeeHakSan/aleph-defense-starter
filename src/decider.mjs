// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'step_up_required',
  'own_notes_zone',
  'class_notices_read_zone',
  'notice_write_instructor_only',
  'unknown_route_deny',
]);

// 구역 규칙(8단계): 엔진이 확인한 method·route·path 가 정확히 맞는 자료 경로만 열어 준다.
// 계약에는 자료 소유자나 강사 역할이 없으므로 판정기는 구역(경로 모양)만 가르고,
// 소유자·강사 권한은 자료 API 가 저장된 값으로 다시 확인한다. 강사 공지 수정은 여기서 열지 않는다.
// 쿼리는 읽지 않고, 기능은 경로의 자료 ID 칸으로만 고른다(export 같은 기능 이름은 자료 ID 로 인정하지 않는다).
const ROUTE = /^(GET|POST|PUT|DELETE) (?:\/api)?(\/(?:notes|notices)(?:\/:id)?)$/u;
const ID_SEGMENT = /^[A-Za-z0-9_-]{1,64}$/u;
const RESERVED_IDS = new Set(['export', 'import', 'all', 'list', 'search', 'download', 'upload', 'bulk', 'backup', 'admin', 'new']);
const NOTE_SHAPES = { GET: [true, false], POST: [false], PUT: [true], DELETE: [true] };

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

function readZone(request) {
  const route = typeof request.route === 'string' ? ROUTE.exec(request.route) : null;
  if (!route || route[1] !== request.method || typeof request.path !== 'string') return null;
  const shape = route[2];
  const path = request.path.replace(/^\/api(?=\/)/u, '');
  const resource = shape.startsWith('/notices') ? 'notice' : 'note';
  const item = shape.endsWith('/:id');
  if (!item) return path === shape ? { resource, method: route[1], item } : null;
  const prefix = shape.slice(0, -3);
  const id = path.startsWith(prefix) ? path.slice(prefix.length) : '';
  if (!ID_SEGMENT.test(id) || RESERVED_IDS.has(id.toLowerCase())) return null;
  return { resource, method: route[1], item };
}

function zoneRule(zone) {
  if (!zone) return { deny: 'unknown_route_deny' };
  if (zone.resource === 'notice') {
    return zone.method === 'GET' ? { allow: 'class_notices_read_zone' } : { deny: 'notice_write_instructor_only' };
  }
  return NOTE_SHAPES[zone.method]?.includes(zone.item) ? { allow: 'own_notes_zone' } : { deny: 'unknown_route_deny' };
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

  const zone = zoneRule(readZone(request));
  if (zone.deny) return answer(request, 'deny', 'zone_not_allowed', [zone.deny]);

  if (isCompositeAnomaly(request)) {
    if (!stepUpDone(request)) return answer(request, 'step_up', 'step_up_required', ['step_up_required']);
    return answer(request, 'allow', 'approved', ['device_registered', zone.allow, 'step_up_required']);
  }

  return answer(request, 'allow', 'approved', ['device_registered', zone.allow]);
}
