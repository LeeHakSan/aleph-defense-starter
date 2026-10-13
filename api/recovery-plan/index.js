import { PolicyRecoveryError } from '../../src/policy-recovery.mjs';
import { loadRecoveryPlan } from '../../src/policy-files.mjs';

// 읽기 전용: 검증한 안전 정책 사본을 다시 읽어 복원할 버전과 시험 정책과의 차이만 보여 준다.
// 정책 사본에는 비밀값이 없고, 이 경로는 아무것도 바꾸지 않는다(실제 되돌리기는 npm run policy:restore).
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  try {
    const { plan } = await loadRecoveryPlan();
    return response.status(200).json(plan);
  } catch (error) {
    if (error instanceof PolicyRecoveryError) {
      return response.status(409).json({ verified: false, error: error.code, message: '검증에 실패해 중단했습니다. 복구하지 않습니다.' });
    }
    return response.status(500).json({ verified: false, error: 'RECOVERY_PLAN_FAILED' });
  }
}
