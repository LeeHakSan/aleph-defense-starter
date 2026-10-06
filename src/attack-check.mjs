// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  // 점검 1: /data.json 에서 메모가 노출되지 않아야 함
  let dataJsonStatus = 'unknown';
  let notesInDataJson = false;
  try {
    const res = await fetch(new URL('/data.json', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    dataJsonStatus = String(res.status);
    if (res.ok) {
      try {
        const data = await res.json();
        notesInDataJson = Array.isArray(data?.notes) && data.notes.length > 0;
      } catch { /* 비정상 응답 */ }
    }
  } catch (e) {
    dataJsonStatus = e.name === 'TimeoutError' ? 'timeout' : 'network_error';
  }

  // 점검 2: /api/notes 가 인증 없이 응답하는지 확인 (2단계 알려진 약점)
  let apiNotesStatus = 'unknown';
  let notesReturned = false;
  try {
    const res = await fetch(new URL('/api/notes', app), {
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    apiNotesStatus = String(res.status);
    if (res.ok) {
      try {
        const data = await res.json();
        notesReturned = Array.isArray(data?.notes) && data.notes.length > 0;
      } catch { /* 비정상 응답 */ }
    }
  } catch (e) {
    apiNotesStatus = e.name === 'TimeoutError' ? 'timeout' : 'network_error';
  }

  return [
    {
      attackId: 'data_json_notes_empty',
      expected: '/data.json에 메모 내용 없음 (notes 배열 비어 있어야 함)',
      observed: notesInDataJson
        ? `/data.json에 메모가 남아 있음 (HTTP ${dataJsonStatus})`
        : `/data.json에 메모 없음 (HTTP ${dataJsonStatus})`,
    },
    {
      attackId: 'api_notes_public_access',
      expected: '/api/notes가 인증 없이 메모를 반환함 (2단계 알려진 약점)',
      observed: notesReturned
        ? `/api/notes에서 메모 반환 확인 (HTTP ${apiNotesStatus}) — 3단계에서 차단 예정`
        : `/api/notes에서 메모 확인 불가 (HTTP ${apiNotesStatus})`,
    },
  ];
}
