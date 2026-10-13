import { createHash } from 'node:crypto';

// 침해 전에 검증한 안전 정책 사본(backups/safe-policy.json)과 현재 시험 정책의 차이를 보여 주고,
// 확인값이 맞을 때만 notes 서비스 정책을 사본 버전으로 되돌린다. 실제 운영 정책은 건드리지 않고,
// 다른 서비스 규칙과 감사 이력은 보존한다. 이 파일은 계산만 하며 파일·네트워크를 쓰지 않는다.
export const SAFE_POLICY_PROJECT = 'choi-bujang-secret-vault';
export const SAFE_POLICY_VERSION = 1;
// backups/safe-policy.json 의 정규화한 내용의 SHA-256. 사본을 고치면 이 값도 검증을 거쳐 함께 바꿔야 한다.
export const SAFE_POLICY_SHA256 = '156d8437f4ae84fc3ff2fb0d94bac7b891e4494c95d066f507e657f28f140ff9';
export const TARGET_SERVICE = 'notes';

const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex');

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export class PolicyRecoveryError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// 사본을 검증한다. 없거나 모양·프로젝트·버전·해시가 하나라도 맞지 않으면 중단한다.
export function verifySafeCopy(text, { expectedSha256 = SAFE_POLICY_SHA256 } = {}) {
  if (typeof text !== 'string' || text.trim() === '') throw new PolicyRecoveryError('policy_copy_missing');
  let copy;
  try {
    copy = JSON.parse(text);
  } catch {
    throw new PolicyRecoveryError('policy_copy_unverified');
  }
  if (!isObject(copy) || copy.schema !== 'aleph.safe-policy.v1' || copy.project !== SAFE_POLICY_PROJECT
      || copy.version !== SAFE_POLICY_VERSION || !isObject(copy.services) || !isObject(copy.services[TARGET_SERVICE])) {
    throw new PolicyRecoveryError('policy_copy_unverified');
  }
  if (sha256(canonicalJson(copy)) !== expectedSha256) throw new PolicyRecoveryError('policy_copy_unverified');
  return copy;
}

function readCurrent(current) {
  if (!isObject(current) || current.schema !== 'aleph.test-policy.v1' || !Number.isSafeInteger(current.version)
      || !isObject(current.services) || !Array.isArray(current.auditLog)) {
    throw new PolicyRecoveryError('test_policy_invalid');
  }
  return current;
}

// 바뀔 항목만 계산한다: notes 서비스의 칸 단위 전/후. 다른 서비스는 목록에만 올리고 바꾸지 않는다.
export function planPolicyRestore(verified, current) {
  const now = readCurrent(current);
  const before = isObject(now.services[TARGET_SERVICE]) ? now.services[TARGET_SERVICE] : {};
  const after = verified.services[TARGET_SERVICE];
  const changes = [];
  for (const field of [...new Set([...Object.keys(before), ...Object.keys(after)])].sort()) {
    if (canonicalJson(before[field]) !== canonicalJson(after[field])) {
      changes.push({ service: TARGET_SERVICE, field, before: before[field] ?? null, after: after[field] ?? null });
    }
  }
  const restoreVersion = verified.version;
  return {
    verified: true,
    service: TARGET_SERVICE,
    currentVersion: now.version,
    restoreVersion,
    changes,
    preservedServices: Object.keys(now.services).filter(name => name !== TARGET_SERVICE).sort(),
    preservedAuditEntries: now.auditLog.length,
    confirmation: changes.length
      ? sha256(canonicalJson({ project: verified.project, restoreVersion, currentVersion: now.version, changes }))
      : null,
  };
}

// 실행 전에 보여 준 계획의 확인값이 같을 때만 새 시험 정책을 돌려준다. 입력은 바꾸지 않는다.
export function applyPolicyRestore(verified, current, confirmation, { at = new Date().toISOString() } = {}) {
  const plan = planPolicyRestore(verified, current);
  if (!plan.changes.length) throw new PolicyRecoveryError('nothing_to_restore');
  if (typeof confirmation !== 'string' || confirmation !== plan.confirmation) throw new PolicyRecoveryError('confirmation_mismatch');
  const now = readCurrent(current);
  return {
    ...now,
    version: now.version + 1,
    services: { ...now.services, [TARGET_SERVICE]: structuredClone(verified.services[TARGET_SERVICE]) },
    auditLog: [...now.auditLog, { at, action: 'restore_policy', service: TARGET_SERVICE,
      restoredFromVersion: verified.version, replacedVersion: now.version, confirmation: plan.confirmation }],
  };
}
