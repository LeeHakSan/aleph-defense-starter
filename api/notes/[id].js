import {
  authenticate, fail, NOTE_COLUMNS, parseId, readJsonObject, readNoteFields, toNote,
} from '../../src/notes-common.mjs';

// 3단계: 로그인만 확인한다. 다른 사용자의 id로도 읽고·고치고·지울 수 있고, 소유자 검사는 4단계에서 붙인다.
export default async function handler(request, response) {
  const session = await authenticate(request, response);
  if (!session) return;
  const { db } = session;

  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const id = parseId(request.query?.id);
  if (!id) return fail(response, 400, 'INVALID_ID');

  if (request.method === 'GET') {
    const { data, error } = await db.from('notes').select(NOTE_COLUMNS).eq('id', id).limit(1);
    if (error) return fail(response, 502, 'NOTES_FETCH_FAILED');
    if (!data.length) return fail(response, 404, 'NOT_FOUND');
    return response.status(200).json(toNote(data[0]));
  }

  if (request.method === 'PUT') {
    const input = readJsonObject(request);
    const fields = input && readNoteFields(input, { requireTitle: false });
    if (!fields || !Object.keys(fields).length) return fail(response, 400, 'INVALID_NOTE');

    const { data, error } = await db.from('notes').update(fields).eq('id', id).select(NOTE_COLUMNS);
    if (error) return fail(response, 502, 'NOTES_WRITE_FAILED');
    if (!data.length) return fail(response, 404, 'NOT_FOUND');
    return response.status(200).json(toNote(data[0]));
  }

  const { data, error } = await db.from('notes').delete().eq('id', id).select('id');
  if (error) return fail(response, 502, 'NOTES_WRITE_FAILED');
  if (!data.length) return fail(response, 404, 'NOT_FOUND');
  return response.status(200).json({ id });
}
