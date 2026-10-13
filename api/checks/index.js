import { runRuleCheck } from '../../src/rule-check.mjs';
import { operationsStatus } from '../../src/operations.mjs';

// GET /api/checks?case=<사례>: 고정된 가상 입력으로 판정기·탐지 규칙을 실행한 결과(ready)만 돌려준다. 사용자 입력을 코드로 실행하지 않는다.
// GET /api/checks: 작전실 화면이 읽는 실제 관측(응답 상태·요청 ID·확인 시각). 메모 본문·토큰·기기 키는 담지 않는다.
export default async function handler(request, response) {
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  if (request.query?.case !== undefined) {
    const result = await runRuleCheck(request.query.case);
    return result ? response.status(200).json(result) : response.status(400).json({ error: 'unknown_check' });
  }

  const status = await operationsStatus();
  return response.status(status.error ? 503 : 200).json(status);
}
