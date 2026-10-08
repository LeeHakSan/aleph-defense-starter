import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';
import { extractAlert, FIXTURE } from './read-alerts.mjs';

const XDR = join(dirname(fileURLToPath(import.meta.url)), '..');
export const RULES_FILE = join(XDR, 'deny-rules.json');
export const ALERTS_LOG = join(XDR, 'alerts.log');
const RULE_TTL_MS = 60 * 60 * 1000;

// block 결정만 출발 주소별 거부 규칙으로 묶는다. 정상(record) 이벤트에 나온 주소는 절대 넣지 않는다.
export function buildDenyRules(entries) {
  const normalSources = new Set(entries.filter((e) => e.decision.action === 'record').map((e) => e.row.srcip));
  const bySource = new Map();
  for (const { alert, row, decision } of entries) {
    if (decision.action !== 'block' || !row.srcip || normalSources.has(row.srcip)) continue;
    const expiresAt = new Date(Date.parse(alert.timestamp) + RULE_TTL_MS).toISOString();
    const rule = bySource.get(row.srcip) ?? { id: `xdr.brute_force.${row.srcip}`, decision: 'deny', srcip: row.srcip, expiresAt, alertIds: [], reason: decision.reason };
    rule.alertIds.push(alert.id);
    if (expiresAt > rule.expiresAt) rule.expiresAt = expiresAt;
    bySource.set(row.srcip, rule);
  }
  return [...bySource.values()];
}

// 판정기 앞에 끼우는 추가 확인 단계. 만료되지 않은 거부 규칙에 걸리면 deny, 아니면 null(판정기 규칙으로 넘김).
export function checkSource(rules, srcip, at) {
  const now = Date.parse(at);
  const hit = rules.find((rule) => rule.srcip === srcip && now < Date.parse(rule.expiresAt));
  return hit ? { decision: 'deny', reasonCode: 'xdr_brute_force', ruleIds: [hit.id] } : null;
}

async function loggedIds() {
  try {
    return new Set((await readFile(ALERTS_LOG, 'utf8')).split('\n').map((line) => line.split('\t')[1]).filter(Boolean));
  } catch {
    return new Set();
  }
}

export async function applyBlocks() {
  const { alerts } = JSON.parse(await readFile(FIXTURE, 'utf8'));
  const entries = [];
  for (const alert of alerts) entries.push({ alert, row: extractAlert(alert), decision: await decide(alert) });

  const rules = buildDenyRules(entries);
  await writeFile(RULES_FILE, `${JSON.stringify({ schema: 'aleph.xdr.deny-rules.v1', moduleKey: 'brute-force', rules }, null, 2)}\n`, 'utf8');

  const seen = await loggedIds();
  const lines = entries
    .filter(({ alert, decision }) => decision.action !== 'record' && !seen.has(alert.id))
    .map(({ alert, row, decision }) => [row.timestamp, alert.id, decision.action, decision.confidence, row.srcip, row.srcuser, decision.reason].join('\t'));
  if (lines.length) await appendFile(ALERTS_LOG, `${lines.join('\n')}\n`, 'utf8');

  // 시험 경보를 다시 흘려 본다: 경보 시각에 그 주소가 막히는지 확인.
  const replay = entries.map(({ alert, row, decision }) => ({ id: alert.id, action: decision.action, blocked: Boolean(checkSource(rules, row.srcip, alert.timestamp)) }));
  return { rules, appended: lines.length, replay };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { rules, appended, replay } = await applyBlocks();
  const blockedAttacks = replay.filter((r) => r.action === 'block' && r.blocked).length;
  const blockedNormal = replay.filter((r) => r.action === 'record' && r.blocked).map((r) => r.id);
  const blockedAmbiguous = replay.filter((r) => r.action === 'alert' && r.blocked).map((r) => r.id);
  console.log(`거부 규칙 ${rules.length}개 · 알림 새로 ${appended}줄`);
  console.log(`다시 흘리기: 명확한 공격 ${blockedAttacks}/${replay.filter((r) => r.action === 'block').length}건 막힘 · 애매한 건 막힘 ${blockedAmbiguous.length}건 · 정상 막힘 ${blockedNormal.length}건${blockedNormal.length ? ` (${blockedNormal.join(', ')})` : ''}`);
  if (blockedNormal.length) process.exitCode = 1;
}
