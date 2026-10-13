// decide 결과를 받아 차단 후보만 판정기 거부 규칙(xdr/deny-rules.json)으로 넣고, 알림을 xdr/alerts.log 에 쌓는다.
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';
import { extractAlert, FIXTURE } from './read-alerts.mjs';

const XDR = join(dirname(fileURLToPath(import.meta.url)), '..');
export const RULES_FILE = join(XDR, 'deny-rules.json');
export const ALERTS_LOG = join(XDR, 'alerts.log');
const RULE_PREFIX = 'xdr.exfiltration.';
const RULE_TTL_MS = 60 * 60 * 1000;

// block 결정만 목적지 주소(data.dstip)별로 묶는다. 정상(record) 이벤트가 쓰는 평소 목적지는 규칙에 넣지 않는다.
const destinationOf = (alert) => (typeof alert?.data?.dstip === 'string' ? alert.data.dstip : '');

export function buildDenyRules(entries) {
  const normalDestinations = new Set(entries.filter((e) => e.decision.action === 'record').map((e) => destinationOf(e.alert)).filter(Boolean));
  const byDestination = new Map();
  for (const { alert, decision } of entries) {
    const dstip = destinationOf(alert);
    if (decision.action !== 'block' || !dstip || normalDestinations.has(dstip)) continue;
    const expiresAt = new Date(Date.parse(alert.timestamp) + RULE_TTL_MS).toISOString();
    const rule = byDestination.get(dstip) ?? { id: `${RULE_PREFIX}${dstip}`, decision: 'deny', dstip, expiresAt, alertIds: [], reason: decision.reason };
    rule.alertIds.push(alert.id);
    if (expiresAt > rule.expiresAt) rule.expiresAt = expiresAt;
    byDestination.set(dstip, rule);
  }
  return [...byDestination.values()];
}

// 판정기 앞에 끼우는 추가 확인 단계. 만료 전 규칙에 걸리는 목적지로 가는 요청은 deny, 아니면 null(판정기 규칙으로 넘김).
export function checkDestination(rules, dstip, at) {
  const now = Date.parse(at);
  const hit = rules.find((rule) => rule.dstip === dstip && now < Date.parse(rule.expiresAt));
  return hit ? { decision: 'deny', reasonCode: 'xdr_exfiltration', ruleIds: [hit.id] } : null;
}

async function readJson(path, fallback) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return fallback;
  }
}

async function loggedIds() {
  try {
    return new Set((await readFile(ALERTS_LOG, 'utf8')).split('\n').map((line) => line.split('\t')[1]).filter(Boolean));
  } catch {
    return new Set();
  }
}

export async function respond() {
  const { alerts } = JSON.parse(await readFile(FIXTURE, 'utf8'));
  const entries = [];
  for (const alert of alerts) entries.push({ alert, row: extractAlert(alert), decision: await decide(alert) });

  const rules = buildDenyRules(entries);
  const others = (await readJson(RULES_FILE, { rules: [] })).rules.filter((rule) => !rule.id.startsWith(RULE_PREFIX));
  await writeFile(RULES_FILE, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', rules: [...others, ...rules] }, null, 2)}\n`, 'utf8');

  const seen = await loggedIds();
  const lines = entries
    .filter(({ alert, decision }) => decision.action !== 'record' && !seen.has(alert.id))
    .map(({ alert, row, decision }) => [row.timestamp, alert.id, decision.action, decision.confidence, row.srcip, row.srcuser ?? '-', decision.reason, destinationOf(alert) || '-'].join('\t'));
  if (lines.length) await appendFile(ALERTS_LOG, `${lines.join('\n')}\n`, 'utf8');

  // 시험 경보를 다시 흘려 본다: 경보 시각에 그 주소가 이 모듈 규칙에 막히는지 확인.
  const replay = entries.map(({ alert, row, decision }) => ({ id: alert.id, action: decision.action, blocked: Boolean(checkDestination(rules, destinationOf(alert), alert.timestamp)) }));
  return { rules, appended: lines.length, replay };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { rules, appended, replay } = await respond();
  const count = (action, blocked) => replay.filter((r) => r.action === action && r.blocked === blocked);
  const blockedNormal = count('record', true).map((r) => r.id);
  console.log(`거부 규칙 ${rules.length}개 · 알림 새로 ${appended}줄`);
  console.log(`다시 흘리기: 명확한 공격 ${count('block', true).length}/${replay.filter((r) => r.action === 'block').length}건 막힘 · 애매한 건 막힘 ${count('alert', true).length}건 · 정상 막힘 ${blockedNormal.length}건${blockedNormal.length ? ` (${blockedNormal.join(', ')})` : ''}`);
  if (blockedNormal.length) process.exitCode = 1;
}
