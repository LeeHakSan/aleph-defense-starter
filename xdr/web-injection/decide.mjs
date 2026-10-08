// patterns.json 의 패턴을 그대로 옮긴 상수. 이 파일은 아무것도 불러오지 않고 혼자 계산한다.
const MIN_REPEATS = 5;
const PATTERNS = Object.freeze([
  { name: 'sql_injection_in_params', technique: 'T1190', match: /doc-(sql|mixed)|union\s+(all\s+)?select|'\s*or\s+\d+\s*=\s*\d+|'\s*--|;\s*drop\s+table/iu },
  { name: 'script_injection_in_params', technique: 'T1190', match: /doc-(script|mixed)|<\s*script|javascript:|onerror\s*=/iu },
  { name: 'path_traversal_repeat', technique: 'T1190', match: /doc-up-repeat|\.\.[/\\]|%2e%2e(%2f|%5c)/iu },
  { name: 'command_injection_in_params', technique: 'T1190', match: /doc-cmd|[;|&]\s*(cat|ls|id|whoami|wget|curl|sh)\b|\$\(/iu },
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

const repeatsOf = (alert) => {
  const n = Number.parseInt(alert?.data?.count ?? '0', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
};

const decodedUrl = (alert) => {
  const raw = typeof alert?.data?.url === 'string' ? alert.data.url : '';
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
};

const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

export function decide(alert) {
  const url = decodedUrl(alert);
  const repeats = repeatsOf(alert);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  const matched = PATTERNS.filter((p) => p.match.test(url)).map((p) => p.name);

  let confidence;
  let reason;
  if (matched.length && repeats >= MIN_REPEATS) {
    // 주입 표기가 뚜렷하고 같은 주소에서 반복: 명확한 공격.
    confidence = level >= 10 ? 0.95 : 0.9;
    reason = `${matched.join('+')} · repeat_same_source (${repeats}번)`;
  } else if (matched.length) {
    confidence = 0.7;
    reason = `${matched.join('+')} · 반복 ${repeats}번 (기준 ${MIN_REPEATS}번 미만)`;
  } else if (tagged) {
    // 경보는 T1190 이라고 했지만 요청 인자에 주입 표기가 보이지 않는다: 애매한 시도.
    confidence = 0.55;
    reason = `T1190 경보지만 주입 패턴 표기 없음 (반복 ${repeats}번)`;
  } else {
    confidence = 0.05;
    reason = '해당 패턴 없음';
  }
  return { action: actionFor(confidence), confidence, reason };
}
