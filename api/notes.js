import { randomUUID } from 'node:crypto';
import { resourceId } from '../src/access.mjs';
import { listOwnNotes } from '../src/notes-list.mjs';
import {
  authenticate, fail, parseId, readJsonObject, readNoteFields,
} from '../src/notes-common.mjs';

export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;
  const { userId, db } = session;

  if (request.method === 'GET') return listOwnNotes(session, response);

  if (request.method === 'POST') {
    const input = readJsonObject(request);
    const fields = input && readNoteFields(input, { requireTitle: true });
    const id = input && (input.id == null || input.id === '' ? randomUUID() : parseId(input.id));
    if (!fields || !id) return fail(response, 400, 'INVALID_NOTE');
    response.setHeader('X-Resource-Id', resourceId('note', id));

    const { error } = await db.from('notes').insert({
      id,
      owner_id: userId,
      title: fields.title,
      content: fields.content ?? '',
    });
    if (error) {
      return error.code === '23505'
        ? fail(response, 409, 'ID_EXISTS')
        : fail(response, 502, 'NOTES_WRITE_FAILED');
    }
    return response.status(201).json({ id });
  }

  response.setHeader('Allow', 'GET, POST');
  return fail(response, 405, 'METHOD_NOT_ALLOWED');
}
