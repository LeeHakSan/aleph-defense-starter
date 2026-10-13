import { protectedAccess } from '../../src/protected-access.mjs';

// GET /api/device/status: 서버가 확인한 기기 승인 상태만 알려 준다(브라우저가 보낸 값은 읽지 않는다).
// POST /api/device/approval: 승인 요청. 서버에 요청을 받아 줄 승인 어댑터가 없으면 접수하지 않는다(503).
export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  const action = request.query?.action;

  if (action === 'status') {
    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    return response.status(200).json(await protectedAccess.status());
  }

  if (action === 'approval') {
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    const { http, body } = await protectedAccess.requestApproval();
    return response.status(http).json(body);
  }

  return response.status(404).json({ error: 'NOT_FOUND' });
}
