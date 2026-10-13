import { noteAccess, resourceId } from './access.mjs';
import {
  fail, forbid, NOTE_COLUMNS, parseId, readJsonObject, readNoteFields, toNote,
} from './notes-common.mjs';

// 서버가 확인한 사용자 ID와 DB의 owner_id가 같은 메모만 다룬다. 요청에 실려 온 owner_id는 믿지 않는다.
export async function handleNote(session, request, response) {
  const { userId, db } = session;

  if (!['GET', 'PUT', 'DELETE'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT, DELETE');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const id = parseId(request.query?.id);
  if (!id) return fail(response, 400, 'INVALID_ID');
  const resource = resourceId('note', id);
  response.setHeader('X-Resource-Id', resource);

  const { data: found, error: findError } = await db
    .from('notes')
    .select(`${NOTE_COLUMNS}, owner_id`)
    .eq('id', id)
    .limit(1);
  if (findError) return fail(response, 502, 'NOTES_FETCH_FAILED');
  if (!found.length) return fail(response, 404, 'NOT_FOUND');
  const access = noteAccess({ userId, ownerId: found[0].owner_id });
  if (!access.allowed) return forbid(response, resource, access.reason);

  if (request.method === 'GET') return response.status(200).json(toNote(found[0]));

  if (request.method === 'PUT') {
    const input = readJsonObject(request);
    if (!input) return fail(response, 400, 'INVALID_NOTE');
    // 소유자를 바꾸려는 요청은 거부한다. 수정은 title·content만 쓰므로 새 행의 소유자도 본인으로 남는다.
    if (input.owner_id !== undefined && parseId(input.owner_id) !== userId) {
      return forbid(response, resource, 'owner_change');
    }
    const fields = readNoteFields(input, { requireTitle: false });
    if (!fields || !Object.keys(fields).length) return fail(response, 400, 'INVALID_NOTE');

    const { data, error } = await db
      .from('notes')
      .update(fields)
      .eq('id', id)
      .eq('owner_id', userId)
      .select(NOTE_COLUMNS);
    if (error) return fail(response, 502, 'NOTES_WRITE_FAILED');
    if (!data.length) return fail(response, 404, 'NOT_FOUND');
    return response.status(200).json(toNote(data[0]));
  }

  const { data, error } = await db
    .from('notes')
    .delete()
    .eq('id', id)
    .eq('owner_id', userId)
    .select('id');
  if (error) return fail(response, 502, 'NOTES_WRITE_FAILED');
  if (!data.length) return fail(response, 404, 'NOT_FOUND');
  return response.status(200).json({ id });
}
