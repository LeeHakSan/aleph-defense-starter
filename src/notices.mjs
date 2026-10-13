import { noticeAccess, resourceId } from './access.mjs';
import { fail, forbid, parseId, readJsonObject, readNoteFields } from './notes-common.mjs';

const NOTICE_COLUMNS = 'id, title, content';
const toNotice = ({ id, title, content }) => ({ id, title, body: content });

// 강사 권한은 instructors 표에 저장된 사용자 ID 만 가진다. 심판 접속(judge)과 조회 오류는 강사가 아니다.
export async function isInstructor({ kind, userId, db }) {
  if (kind !== 'student') return false;
  const { data, error } = await db.from('instructors').select('user_id').eq('user_id', userId).limit(1);
  if (error) throw new Error('ROLE_LOOKUP_FAILED');
  return data.length > 0;
}

export async function listNotices(session, response) {
  response.setHeader('X-Resource-Id', resourceId('notice'));
  const { data, error } = await session.db
    .from('notices')
    .select(NOTICE_COLUMNS)
    .order('created_at', { ascending: true });
  if (error) return fail(response, 502, 'NOTICES_FETCH_FAILED');
  return response.status(200).json(data.map(toNotice));
}

export async function handleNotice(session, request, response) {
  if (!['GET', 'PUT'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT');
    return fail(response, 405, 'METHOD_NOT_ALLOWED');
  }

  const id = parseId(request.query?.id);
  if (!id) return fail(response, 400, 'INVALID_ID');
  const resource = resourceId('notice', id);
  response.setHeader('X-Resource-Id', resource);

  let instructor = false;
  if (request.method === 'PUT') {
    try {
      instructor = await isInstructor(session);
    } catch {
      return fail(response, 502, 'ROLE_LOOKUP_FAILED');
    }
  }
  // 수정 권한은 공지가 있는지 알려 주기 전에 확인한다.
  const access = noticeAccess({ method: request.method, isInstructor: instructor });
  if (!access.allowed) return forbid(response, resource, access.reason);

  if (request.method === 'GET') {
    const { data, error } = await session.db.from('notices').select(NOTICE_COLUMNS).eq('id', id).limit(1);
    if (error) return fail(response, 502, 'NOTICES_FETCH_FAILED');
    if (!data.length) return fail(response, 404, 'NOT_FOUND');
    return response.status(200).json(toNotice(data[0]));
  }

  const input = readJsonObject(request);
  const fields = input && readNoteFields(input, { requireTitle: false });
  if (!fields || !Object.keys(fields).length) return fail(response, 400, 'INVALID_NOTE');

  const { data, error } = await session.db
    .from('notices')
    .update({ ...fields, updated_at: new Date().toISOString() })
    .eq('id', id)
    .select(NOTICE_COLUMNS);
  if (error) return fail(response, 502, 'NOTICES_WRITE_FAILED');
  if (!data.length) return fail(response, 404, 'NOT_FOUND');
  return response.status(200).json(toNotice(data[0]));
}
