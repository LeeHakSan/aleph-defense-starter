import { authenticate } from '../../src/notes-common.mjs';
import { handleNote } from '../../src/notes-item.mjs';

export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;
  return handleNote(session, request, response);
}
