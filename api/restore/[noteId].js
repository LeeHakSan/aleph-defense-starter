import { authenticate, fail } from '../../src/notes-common.mjs';
import { restoreNote } from '../../src/restore.mjs';

// 서비스 notes 의 복구 경로: POST /api/restore/:noteId. 로그인한 본인의 메모 한 건만 사본에서 되돌린다.
export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  return restoreNote(session, request, response);
}
