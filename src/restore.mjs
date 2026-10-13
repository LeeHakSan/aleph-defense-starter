import { resourceId } from './access.mjs';
import { fail, forbid, parseId } from './notes-common.mjs';

// 한 건 복구. 소유자는 검증된 로그인에서만 얻고, 요청 본문·헤더·쿼리의 소유자·본문·해시·역할은 읽지 않는다.
// 사본 대조(소유자·ID·내용 해시)와 되돌리기는 DB 함수가 한 트랜잭션에서 한다. 사본은 복구 직전에 매번 다시 읽어 검증한다.
export async function restoreNote({ userId, db }, request, response) {
  const noteId = parseId(request.query?.noteId);
  if (!noteId) return fail(response, 400, 'INVALID_ID');
  const resource = resourceId('note', noteId);
  response.setHeader('X-Resource-Id', resource);

  const { data, error } = await db.rpc('vault_restore_note', { p_note_id: noteId, p_user_id: userId });
  if (error || data === null || typeof data !== 'object') return fail(response, 502, 'RESTORE_FAILED');

  switch (data.status) {
    case 'restored':
      return response.status(200).json({
        restored: true, action: data.action, id: data.id, ownerId: data.ownerId, contentSha256: data.contentSha256,
      });
    case 'no_backup':
      return fail(response, 404, 'NO_BACKUP');
    case 'forbidden':
    case 'owner_conflict':
      return forbid(response, resource, 'not_owner');
    case 'backup_unverified':
      return fail(response, 409, 'BACKUP_UNVERIFIED');
    default:
      return fail(response, 502, 'RESTORE_FAILED');
  }
}
