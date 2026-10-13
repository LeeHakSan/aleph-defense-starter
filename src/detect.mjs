// 9단계 탐지 함수입니다. 반 엔진이 검증해 넘긴 가상 사건만 읽고, 아무것도 불러오지 않으며 파일·네트워크를 쓰지 않습니다.
// 읽는 값은 시각(at)·요청 종류(method)·가명 사용자(identity.sub) 세 가지뿐이고, 저장하거나 출력하지 않습니다.
// 같은 sub 의 GET 이 어느 10분 구간에서든 120건을 넘을 때만 그 sub 한 명에 대한 회수를 제안합니다.
// 이 함수는 제안만 돌려줍니다. 실제 회수와 접속 차단은 반 엔진이 집행합니다.
const WINDOW_MS = 10 * 60 * 1000;
const LIMIT = 120;

function readEvent(event) {
  if (event === null || typeof event !== 'object') return null;
  const at = typeof event.at === 'string' ? Date.parse(event.at) : event.at;
  const sub = event.identity?.sub;
  if (typeof at !== 'number' || !Number.isFinite(at)) return null;
  if (typeof event.method !== 'string' || event.method.toUpperCase() !== 'GET') return null;
  if (typeof sub !== 'string' || sub === '') return null;
  return { at, sub };
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const times = new Map();
  for (const event of events) {
    const read = readEvent(event);
    if (!read) continue;
    if (!times.has(read.sub)) times.set(read.sub, []);
    times.get(read.sub).push(read.at);
  }

  // 사용자별로 시간순 정렬 뒤, 구간 길이가 10분 이하인 묶음이 120건을 넘는 첫 순간을 찾는다.
  // 여러 사용자가 넘으면 먼저 넘은 한 명만 제안한다(대상은 한 명으로 한정).
  let offender = null;
  for (const [sub, list] of times) {
    if (list.length <= LIMIT) continue;
    list.sort((a, b) => a - b);
    for (let start = 0, end = LIMIT; end < list.length; end += 1) {
      while (list[end] - list[start] > WINDOW_MS) start += 1;
      if (end - start + 1 > LIMIT) {
        if (!offender || list[end] < offender.at || (list[end] === offender.at && sub < offender.sub)) {
          offender = { sub, at: list[end] };
        }
        break;
      }
    }
  }

  return offender
    ? { action: 'propose_revocation', reasonCode: 'burst_read', subject: offender.sub }
    : { action: 'observe' };
}
