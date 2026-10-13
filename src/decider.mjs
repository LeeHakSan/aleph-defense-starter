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

// 구역 규칙(8단계): 엔진이 확인한 사용자(subjectId)·method·정확한 경로로 자료 구역을 가른다(기기는 위 기기 규칙이 먼저 본다).
// 자기 메모 구역은 이 자료실 주인으로 등록된 사용자만 연다. 다른 사용자가 같은 메모 경로를 요청하면 거부한다.
// 강사 공지는 읽기만 열고, 수정은 계약에 강사 역할이 없으므로 판정기에서 열지 않는다(수정 권한은 자료 API 가 저장된 강사로 따로 확인).
// 쿼리가 붙은 요청과 자료 ID 자리의 기능 이름(export 등)은 정확한 경로가 아니므로 거부한다.
// 주인 목록에는 엔진 실습 요청(scripts/fixture-7.mjs)의 가상 주인만 있다. 실제 주인은 엔진이 확인한 가명 주체 ID 로 추가한다.
const VAULT_OWNERS = Object.freeze(['learner_fixture']);
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
  if (request.queryLength !== 0) return null;
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

function zoneRule(request, zone) {
  if (!zone) return { deny: 'unknown_route_deny' };
  if (zone.resource === 'notice') {
    return zone.method === 'GET' ? { allow: 'class_notices_read_zone' } : { deny: 'notice_write_instructor_only' };
  }
  if (!NOTE_SHAPES[zone.method]?.includes(zone.item)) return { deny: 'unknown_route_deny' };
  return VAULT_OWNERS.includes(request.subjectId) ? { allow: 'own_notes_zone' } : { deny: 'own_notes_zone' };
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

  const zone = zoneRule(request, readZone(request));
  if (zone.deny) return answer(request, 'deny', 'zone_not_allowed', [zone.deny]);

  if (isCompositeAnomaly(request)) {
    if (!stepUpDone(request)) return answer(request, 'step_up', 'step_up_required', ['step_up_required']);
    return answer(request, 'allow', 'approved', ['device_registered', zone.allow, 'step_up_required']);
  }

  return answer(request, 'allow', 'approved', ['device_registered', zone.allow]);
}
