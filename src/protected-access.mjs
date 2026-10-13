// 보호 자료 요청의 기기 승인을 서버에서 확인하는 자리다.
// 승인 여부는 서버가 연결한 어댑터(제공 엔진이 확인한 결과)만 정한다. 브라우저가 보낸 approved·role·deviceRegistered·헤더·쿼리·본문은
// 읽지 않고, 앱을 설치했다는 표시도 승인 근거가 아니다. 어댑터가 없거나 알 수 없는 답을 주면 막는다(열어 주는 쪽으로 기울지 않는다).
// 어댑터는 ({ purpose }, login) 을 받아 'approved' | 'denied' | 'pending' 중 하나로 답한다. 지금은 연결된 어댑터가 없다.
const UNAVAILABLE = 'device_verification_unavailable';
const DENIED = 'device_not_approved';

export function createProtectedAccess({ adapter = null } = {}) {
  async function ask(purpose, login) {
    if (typeof adapter !== 'function') return null;
    try {
      const verdict = await adapter({ purpose }, login ?? null);
      return ['approved', 'denied', 'pending'].includes(verdict) ? verdict : null;
    } catch {
      return null;
    }
  }

  return {
    // 로그인 확인 다음에 모든 보호 자료 요청이 지난다. 승인된 경우에만 ok.
    async check(login) {
      const verdict = await ask('request', login);
      if (verdict === 'approved') return { ok: true };
      if (verdict === 'denied' || verdict === 'pending') return { ok: false, status: 403, error: DENIED };
      return { ok: false, status: 503, error: UNAVAILABLE };
    },

    // 승인 상태 표시용. 서버가 승인했다고 확인한 경우에만 approved·connected 가 true.
    async status() {
      const verdict = await ask('status', null);
      return {
        schema: 'aleph.device-status.v1',
        connected: verdict !== null,
        approved: verdict === 'approved',
        approval: verdict ?? 'unavailable',
        reasonCode: verdict === null ? UNAVAILABLE : verdict === 'approved' ? 'approved' : DENIED,
      };
    },

    // 승인 요청. 요청을 받아 줄 어댑터가 없으면 접수하지 않는다.
    async requestApproval() {
      const verdict = await ask('approval', null);
      if (verdict === 'approved') return { http: 200, body: { approval: 'approved', approved: true } };
      if (verdict === 'pending') return { http: 202, body: { approval: 'pending', approved: false } };
      if (verdict === 'denied') return { http: 403, body: { error: DENIED, approval: 'denied', approved: false } };
      return { http: 503, body: { error: UNAVAILABLE, approval: 'unavailable', approved: false } };
    },
  };
}

export const protectedAccess = createProtectedAccess();
