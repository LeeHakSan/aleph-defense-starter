// patterns.json 의 패턴을 그대로 옮긴 상수. 이 파일은 아무것도 불러오지 않고, 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고 혼자 계산한다.
const MIN_REPEATS = 3;
// 원격 조회 구문: jndi: 뒤에 조회 방식과 :// 가 완성된 모양일 때만 맞는다 (CVE-2021-44228 형태, T1190).
const LOOKUP = /\$\{\s*jndi\s*:\s*(ldaps?|rmi|dns|iiop|nis|corba|https?):\/\/[^}\s]+\}?/iu;
const PATTERNS = Object.freeze({
  jndi_lookup_in_url: { technique: 'T1190', match: LOOKUP },
  jndi_lookup_in_header: { technique: 'T1190', match: LOOKUP },
  lookup_in_both_header_and_url: { technique: 'T1190' },
  repeat_same_source: { technique: 'T1190' },
  vuln_scanner_trace: { technique: 'T1190', match: /\b(nuclei|zgrab|log4j-scan|masscan|nikto)\b|[?&]probe=/iu },
  cve_keyword_without_lookup: { technique: 'T1190', match: /CVE-2021-44228|jndi/iu },
});

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;

const text = (value) => (typeof value === 'string' ? value : '');
const decoded = (value) => {
  const raw = text(value);
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
};
const repeatsOf = (alert) => {
  const n = Number.parseInt(alert?.data?.count ?? '0', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
};
const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

export function decide(alert) {
  const url = decoded(alert?.data?.url);
  const header = decoded(alert?.data?.useragent);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  const repeats = repeatsOf(alert);

  const inUrl = PATTERNS.jndi_lookup_in_url.match.test(url);
  const inHeader = PATTERNS.jndi_lookup_in_header.match.test(header);
  const scanner = PATTERNS.vuln_scanner_trace.match.test(`${url} ${header}`);
  const keyword = PATTERNS.cve_keyword_without_lookup.match.test(`${url} ${header}`);

  let confidence;
  let reason;
  if (inUrl || inHeader) {
    // 완성된 원격 조회 구문: 명확한 공격. 겹치는 신호가 많을수록 확신도를 조금씩 올린다.
    const names = [];
    if (inUrl) names.push('jndi_lookup_in_url');
    if (inHeader) names.push('jndi_lookup_in_header');
    confidence = 0.9;
    if (inUrl && inHeader) { confidence += 0.03; names.push('lookup_in_both_header_and_url'); }
    if (repeats >= MIN_REPEATS) { confidence += 0.02; names.push('repeat_same_source'); }
    if (scanner) { confidence += 0.02; names.push('vuln_scanner_trace'); }
    if (level >= 12) confidence += 0.03;
    confidence = Math.min(0.99, Math.round(confidence * 100) / 100);
    reason = `${names.join('+')} · CVE-2021-44228 (T1190, 수준 ${level})`;
  } else if (keyword || scanner) {
    // 번호·이름·점검 도구 흔적만 있고 구문은 완성되지 않았다: 애매한 시도. 알리기만 한다.
    confidence = tagged ? 0.6 : 0.5;
    reason = `${keyword ? 'cve_keyword_without_lookup' : 'vuln_scanner_trace'} · 완성된 원격 조회 구문 없음 (반복 ${repeats}번)`;
  } else if (tagged) {
    // 경보는 T1190 이라고 했지만 요청에 조회 구문도 관련 글자도 없다: 애매한 시도.
    confidence = 0.55;
    reason = `T1190 경보지만 원격 조회 구문 없음 (수준 ${level}, 반복 ${repeats}번)`;
  } else {
    confidence = 0.05;
    reason = '해당 패턴 없음';
  }
  return { action: actionFor(confidence), confidence, reason };
}
