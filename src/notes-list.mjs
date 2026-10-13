import { resourceId } from './access.mjs';
import { fail, NOTE_COLUMNS, toNote } from './notes-common.mjs';

// 검증된 로그인 사용자가 소유한 메모만 DB 조건(owner_id)으로 고른다.
export async function listOwnNotes({ userId, db }, response) {
  response.setHeader('X-Resource-Id', resourceId('note'));
  const { data, error } = await db
    .from('notes')
    .select(NOTE_COLUMNS)
    .eq('owner_id', userId)
    .order('created_at', { ascending: true });
  if (error) return fail(response, 502, 'NOTES_FETCH_FAILED');
  return response.status(200).json(data.map(toNote));
}
