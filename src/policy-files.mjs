import { readFile } from 'node:fs/promises';
import { PolicyRecoveryError, planPolicyRestore, verifySafeCopy } from './policy-recovery.mjs';

export const SAFE_COPY_URL = new URL('../backups/safe-policy.json', import.meta.url);
export const TEST_POLICY_URL = new URL('../policy/test-policy.json', import.meta.url);

// 호출할 때마다 파일을 다시 읽는다(메모리에 담아 두지 않는다). 사본이 없으면 중단한다.
export async function readVerifiedCopy(url = SAFE_COPY_URL) {
  let text;
  try {
    text = await readFile(url, 'utf8');
  } catch {
    throw new PolicyRecoveryError('policy_copy_missing');
  }
  return verifySafeCopy(text);
}

export async function readTestPolicy(url = TEST_POLICY_URL) {
  try {
    return JSON.parse(await readFile(url, 'utf8'));
  } catch {
    throw new PolicyRecoveryError('test_policy_invalid');
  }
}

// 복원할 버전과 바뀔 범위를 실행 전에 계산만 한다. 아무것도 쓰지 않는다.
export async function loadRecoveryPlan({ copyUrl = SAFE_COPY_URL, policyUrl = TEST_POLICY_URL } = {}) {
  const verified = await readVerifiedCopy(copyUrl);
  const current = await readTestPolicy(policyUrl);
  return { verified, current, plan: planPolicyRestore(verified, current) };
}
