import { authenticate } from '../../src/notes-common.mjs';
import { handleNotice } from '../../src/notices.mjs';

// 읽기는 로그인한 사용자 모두, 수정은 저장된 강사 권한이 있을 때만 한다.
export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;
  return handleNotice(session, request, response);
}
