import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyPolicyRestore, PolicyRecoveryError } from '../src/policy-recovery.mjs';
import { loadRecoveryPlan, TEST_POLICY_URL } from '../src/policy-files.mjs';

// plan: 복원할 버전과 바뀔 항목만 보여 준다(아무것도 쓰지 않는다).
// restore <확인값>: 방금 보여 준 계획의 확인값이 같을 때만 policy/test-policy.json 의 notes 정책을 사본 버전으로 되돌린다.
const MESSAGES = {
  policy_copy_missing: '안전 정책 사본(backups/safe-policy.json)이 없어 중단합니다.',
  policy_copy_unverified: '안전 정책 사본의 검증(프로젝트·버전·SHA-256)에 실패해 중단합니다.',
  test_policy_invalid: '시험 정책(policy/test-policy.json)을 읽을 수 없어 중단합니다.',
  nothing_to_restore: '시험 정책이 이미 검증한 사본과 같습니다. 바꿀 것이 없습니다.',
  confirmation_mismatch: '확인값이 방금 보여 준 계획과 다릅니다. 계획을 다시 보고 그 확인값으로 실행하세요.',
};

export async function run(argv, { write = text => process.stdout.write(`${text}\n`), policyUrl = TEST_POLICY_URL, copyUrl } = {}) {
  const [command, confirmation] = argv;
  if (command !== 'plan' && command !== 'restore') {
    write('사용법: npm run policy:plan | npm run policy:restore -- <확인값>');
    return 2;
  }
  try {
    const { verified, current, plan } = await loadRecoveryPlan({ policyUrl, ...(copyUrl ? { copyUrl } : {}) });
    write(`검증한 사본: 프로젝트 ${verified.project} · 복원할 버전 ${plan.restoreVersion} (현재 시험 정책 버전 ${plan.currentVersion})`);
    write(`바뀔 항목 ${plan.changes.length}개 (서비스 ${plan.service})`);
    for (const change of plan.changes) {
      write(`  - ${change.field}: ${JSON.stringify(change.before)} -> ${JSON.stringify(change.after)}`);
    }
    write(`보존: 다른 서비스 규칙 ${plan.preservedServices.join(', ') || '없음'} · 감사 기록 ${plan.preservedAuditEntries}건`);
    if (command === 'plan') {
      write(plan.confirmation ? `확인값: ${plan.confirmation}` : MESSAGES.nothing_to_restore);
      return 0;
    }
    const next = applyPolicyRestore(verified, current, confirmation);
    await writeFile(policyUrl, `${JSON.stringify(next, null, 2)}\n`, 'utf8');
    write(`복원했습니다: notes 정책을 사본 버전 ${plan.restoreVersion}으로 되돌리고 시험 정책 버전을 ${next.version}로 올렸습니다. 감사 기록 ${next.auditLog.length}건.`);
    return 0;
  } catch (error) {
    if (error instanceof PolicyRecoveryError) {
      write(MESSAGES[error.code] ?? error.code);
      return 1;
    }
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await run(process.argv.slice(2));
}
