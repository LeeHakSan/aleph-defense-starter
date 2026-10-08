// 확인용 읽기 모듈. decide.mjs 는 이 파일을 불러오지 않는다.
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures', 'web-injection.json');

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

export function extractAlert(alert) {
  return {
    timestamp: mask(alert?.timestamp ?? null),
    srcip: mask(alert?.data?.srcip ?? null),
    srcuser: mask(alert?.data?.srcuser ?? null),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : null,
    description: mask(alert?.rule?.description ?? null),
  };
}

export async function readAlerts(path = FIXTURE) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (!Array.isArray(fixture?.alerts)) throw new Error('경보 묶음 형식이 아닙니다.');
  return { total: fixture.alerts.length, rows: fixture.alerts.map(extractAlert) };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { total, rows } = await readAlerts();
  for (const row of rows) console.log(JSON.stringify(row));
  console.log(`경보 ${total}건 · 뽑은 줄 ${rows.length}줄 · ${total === rows.length ? '일치' : '불일치'}`);
}
