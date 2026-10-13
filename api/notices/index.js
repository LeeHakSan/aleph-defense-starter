import { authenticate, fail } from '../../src/notes-common.mjs';
import { listNotices } from '../../src/notices.mjs';

export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }
  return listNotices(session, response);
}
