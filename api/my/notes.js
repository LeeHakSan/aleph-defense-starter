import { authenticate, fail } from '../../src/notes-common.mjs';
import { listOwnNotes } from '../../src/notes-list.mjs';

// 자기 메모 목록의 명시적 경로. 검증된 로그인 사용자의 메모만 DB에서 고른다.
export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  return listOwnNotes(session, response);
}
