// 자원 ID와 구역 권한 판단. 소유자와 강사 여부는 서버가 저장소에서 읽은 값으로만 판단하고,
// 요청 본문·화면 메뉴·토큰에 실려 온 role 이나 owner_id 는 읽지 않는다.

export const RESOURCE_TYPES = Object.freeze({ note: 'note', notice: 'notice' });

// 메모는 note:<id>, 강사 공지는 notice:<id>. 목록처럼 특정 자료가 없으면 note:* 처럼 쓴다.
export const resourceId = (type, id = '*') => `${RESOURCE_TYPES[type]}:${id}`;

// 자기 메모 구역: 저장된 owner_id 가 확인된 사용자와 같을 때만 열린다. 주인 없는 메모는 아무에게도 열지 않는다.
export function noteAccess({ userId, ownerId }) {
  const same = typeof ownerId === 'string' && typeof userId === 'string' && ownerId.toLowerCase() === userId.toLowerCase();
  return same ? { allowed: true } : { allowed: false, reason: 'not_owner' };
}

// 강사 공지 구역: 읽기는 로그인한 모두, 수정은 저장된 강사 권한이 있을 때만. 그 밖의 동작은 열지 않는다.
export function noticeAccess({ method, isInstructor }) {
  if (method === 'GET') return { allowed: true };
  if (method === 'PUT') return isInstructor === true ? { allowed: true } : { allowed: false, reason: 'not_instructor' };
  return { allowed: false, reason: 'method_not_allowed' };
}
