import { readFileSync } from 'node:fs';
import { extractAlert } from './read-alerts.mjs';

const { patterns } = JSON.parse(readFileSync(new URL('./patterns.json', import.meta.url), 'utf8'));
const burst = patterns.find((p) => p.name === 'failure_burst_same_source');
const spray = patterns.find((p) => p.name === 'password_spray_many_accounts');

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const JEV_TIMEOUT_MS = 3000;

const failuresOf = (alert) => {
  const n = Number.parseInt(alert?.data?.count ?? '0', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
};

// 계정 수는 data.accounts 목록을 먼저 보고, 없으면 설명의 "계정 N개"를 읽는다.
const accountsOf = (alert) => {
  const list = alert?.data?.accounts;
  if (typeof list === 'string' && list.trim()) return new Set(list.split(',').map((s) => s.trim()).filter(Boolean)).size;
  const match = /계정\s*(\d+)\s*개/u.exec(alert?.rule?.description ?? '');
  return match ? Number(match[1]) : 0;
};

const actionFor = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
const round = (value) => Math.round(value * 100) / 100;

// Jev는 JEV_URL이 설정돼 있을 때만 부른다. 응답이 없거나 형식이 틀리면 null을 돌려준다.
async function askJevOverHttp(summary) {
  const url = process.env.JEV_URL;
  if (!url) return null;
  try {
    const response = await fetch(url, {
      method: 'POST',
      signal: AbortSignal.timeout(JEV_TIMEOUT_MS),
      headers: {
        'Content-Type': 'application/json',
        ...(process.env.JEV_API_KEY ? { Authorization: `Bearer ${process.env.JEV_API_KEY}` } : {}),
      },
      body: JSON.stringify({ task: 'brute-force-confidence', alert: summary }),
    });
    if (!response.ok) return null;
    const { confidence } = await response.json();
    return confidence;
  } catch {
    return null;
  }
}

export async function decide(alert, { askJev = askJevOverHttp } = {}) {
  const failures = failuresOf(alert);
  const accounts = accountsOf(alert);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const tagged = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.some((t) => String(t).startsWith('T1110'));

  // 명확한 공격: 근거가 있는 패턴에 맞을 때만 막는다.
  const matched = accounts >= spray.minAccounts ? spray : failures >= burst.minFailures ? burst : null;
  if (matched) {
    const confidence = level >= 10 ? 0.95 : 0.9;
    const detail = matched === spray ? `계정 ${accounts}개` : `실패 ${failures}건`;
    return { action: 'block', confidence, reason: `${matched.name} (${matched.technique}, ${detail})` };
  }

  // 정상 이벤트: 로그인 실패가 없거나 1건뿐이고 무차별 대입 표시도 없다.
  if (failures < 2 && !tagged) {
    return { action: 'record', confidence: 0.05, reason: `해당 패턴 없음 (로그인 실패 ${failures}건)` };
  }

  // 애매한 시도: 실패는 있지만 패턴 기준에 못 미친다. Jev에게 확신도를 묻고, 응답이 없으면 알림으로 남긴다.
  const below = `${burst.name} 기준 미달 (실패 ${failures}건, 계정 ${accounts}개)`;
  let answer = null;
  try {
    answer = await askJev(extractAlert(alert));
  } catch {
    answer = null;
  }
  if (typeof answer !== 'number' || !Number.isFinite(answer) || answer < 0 || answer > 1) {
    return { action: 'alert', confidence: ALERT_AT, reason: `${below} · Jev 응답 없음` };
  }
  const confidence = round(answer);
  return { action: actionFor(confidence), confidence, reason: `${below} · Jev 확신도 ${confidence}` };
}
