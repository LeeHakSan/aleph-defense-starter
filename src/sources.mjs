// 12단계: 탈환 작전실과 서버 점검 기록에 붙이는 출처 구분입니다.
// 학생이 만든 것과 제공 엔진(ALEPH SDP 엔진)을 두 갈래로만 나눕니다. 비밀값은 넣지 않습니다.
export const ENGINE = 'ALEPH SDP 엔진';

export const SOURCES = Object.freeze({
  student: Object.freeze({
    label: '학생이 만든 것',
    parts: Object.freeze([
      '판정기(src/decider.mjs)', '탐지 규칙(src/detect.mjs)', '접속 앱(public/)',
      '자료실(api/, supabase/)', '점검 코드(src/attack-check.mjs, src/rule-check.mjs)', '작전실(public/operations.html, api/checks)',
    ]),
  }),
  engine: Object.freeze({
    label: '제공 엔진',
    name: ENGINE,
    role: '요청마다 신원·기기 등록·재로그인을 확인한 뒤 학생 판정기 decide(request)를 부르고 결과를 집행하며, 학생 탐지 규칙 detect(events)의 회수 제안을 집행하고, 요청 서명을 확인합니다. 이 저장소에는 엔진 코드가 없고, 이 기록에는 엔진 집행 결과가 없습니다(미실행).',
  }),
});
