// 비밀값처럼 보이는 조각은 출력하지 않는다. 원본 경보는 읽기만 한다.
const SECRET_LIKE = [
  /\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S+/giu,
  /\bBearer\s+\S+/gu,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)?/gu,
  /\b(sb_secret|sb_publishable|sk)[_-][A-Za-z0-9_-]{8,}/gu,
  /\b[A-Za-z0-9+/_-]{32,}={0,2}/gu,
];

export function mask(value) {
  if (typeof value !== 'string') return value;
  return SECRET_LIKE.reduce((text, pattern) => text.replace(pattern, '[가림]'), value);
}

// 시각·출발 주소·계정·규칙 수준·설명 다섯 가지만 뽑는다.
export function extractAlert(alert) {
  return {
    timestamp: mask(alert?.timestamp ?? null),
    srcip: mask(alert?.data?.srcip ?? null),
    srcuser: mask(alert?.data?.srcuser ?? null),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: mask(alert?.rule?.description ?? null),
  };
}
