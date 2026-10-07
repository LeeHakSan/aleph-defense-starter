import { randomUUID } from 'node:crypto';
import {
  authenticate, fail, NOTE_COLUMNS, parseId, readJsonObject, readNoteFields, toNote,
} from '../src/notes-common.mjs';

export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;
  const { userId, db } = session;

  if (request.method === 'GET') {
    const { data, error } = await db
      .from('notes')
      .select(NOTE_COLUMNS)
      .eq('owner_id', userId)
      .order('created_at', { ascending: true });
    if (error) return fail(response, 502, 'NOTES_FETCH_FAILED');
    return response.status(200).json(data.map(toNote));
  }

  if (request.method === 'POST') {
    const input = readJsonObject(request);
    const fields = input && readNoteFields(input, { requireTitle: true });
    const id = input && (input.id == null || input.id === '' ? randomUUID() : parseId(input.id));
    if (!fields || !id) return fail(response, 400, 'INVALID_NOTE');

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
