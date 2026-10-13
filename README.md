# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계의 출발점에서는 `/`의 점령된 가상 자료실이 열려 있었고 `/data.json`에도 같은 가상 메모가 공개돼 있었습니다. 지금 상태는 아래 "현재 작동하는 기능"을 보세요. 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 `npm run bundle`이 실행하는 자기 점검으로, 실제 배포 주소에 로그인 없는 요청·위조 토큰 요청·공개용 `anon` 키 직접 요청을 보내 결과만 기록합니다.

## 현재 작동하는 기능 (12단계)

- `/`(11단계부터 접속 화면): 설치형 웹앱의 접속 화면입니다. `manifest`(`/manifest.webmanifest`, 앱 이름 "최 부장 자료실"·시작 주소·`standalone`·아이콘)를 연결하고, 서버가 알려 주는 **기기 승인 상태**와 승인 요청 버튼, 오프라인 안내만 보여 줍니다. 로그인 폼·메모 목록·편집 화면은 없습니다. 앱을 설치했다는 표시나 버튼만으로는 기기를 승인하지 않으며, 「자료실 열기」는 서버가 `approved`와 `connected`를 모두 `true`로 알려 줄 때만 켜집니다. 기존 로그인·메모 화면은 `/vault.html`로 옮겼고(기능은 그대로), 서버가 승인했다고 확인하기 전에는 로그인 폼도 메모 요청도 없습니다(자료실 화면 코드 `/vault-app.js`는 승인 확인 뒤에만 불러옵니다). 로그인 토큰은 브라우저 저장소(`localStorage`·`sessionStorage`·IndexedDB·쿠키·캐시)에 넣지 않고 화면 코드의 메모리에만 두므로 새로고침하면 다시 로그인합니다. 기기 키는 이 저장소에 없습니다. 화면은 서버 함수(`/api/*`)만 부르고, 화면 코드에는 Supabase 주소·공개 키·외부 라이브러리가 없습니다.
- `POST /api/auth/login`·`/refresh`·`/logout`: 서버가 Supabase Auth를 공개 키(서버 환경 변수 `SUPABASE_PUBLISHABLE_KEY`)로 대신 부르고, 화면에는 로그인 토큰·갱신 토큰·만료 시각·사용자 ID·이메일만 돌려줍니다. 틀린 정보는 401(`LOGIN_FAILED`), 공개 키 설정 문제는 503(`AUTH_MISCONFIGURED`)입니다. 화면은 토큰이 만료되면 알아서 갱신하고, 갱신이 안 되면 로그아웃 상태로 돌아갑니다.
- `GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id`: 서버가 요청의 로그인 토큰을 `src/verify-login.mjs`로 확인합니다. 토큰이 없거나 틀리면 자료 없이 401입니다.
- 소유자 검사: 서버가 확인한 사용자 ID와 DB의 `owner_id`를 비교해, 다른 사용자(또는 주인 없는) 메모의 조회·수정·삭제는 403으로 거부합니다. 없는 id는 404입니다. 목록은 본인 메모만 돌려주고, 추가할 때는 확인된 ID를 `owner_id`로 저장합니다. 요청에 실려 온 `owner_id`·사용자 ID·역할은 믿지 않으며, 소유자를 바꾸려는 수정은 403입니다.
- `/data.json`: 메모 없이 `{"notes":[]}`만 공개합니다. `/aleph.json`: 빌드가 단계·커밋·주소와 허용 경로(`allowedRoutes`: 판정기가 여는 읽기 구역 3개 `GET /api/my/notes`, `GET /api/notes/:id`, `GET /notes/:id`), 원본 자료 주소(`originalApiUrl`)를 기록합니다. 심판은 `aleph.config.json`이 아니라 이 배포본의 값을 읽습니다.
- DB 권한: `public.notes`는 RLS가 켜져 있고 `anon`·`authenticated`의 직접 권한을 모두 회수했습니다(`supabase/step4-rls.sql`, `supabase/step5-revoke-direct.sql`). 정책 4개(`auth.uid() = owner_id`)는 권한이 다시 열릴 때를 대비한 안전장치로 남겼습니다. 메모는 서버 함수가 서버 전용 키로만 읽고 쓰며, 원본 자료 주소는 `aleph.config.json`의 `originalApiUrl`에 적었습니다. 기존 샘플 메모 4건은 시험 계정 A 소유로 연결했고, 시험 계정 B 소유의 시험 메모가 1건 있습니다.
- 판정기(`src/decider.mjs`): `device_registered` 규칙 추가. 엔진이 확인한 `deviceRegistered`가 `true`면 허용(`approved`), `false`이거나 값이 없으면 거부(`device_not_registered`)합니다.
- 판정기 `step_up_required` 규칙(7단계): 엔진이 `signals.source: "judge_fixture"`로 표시한 가상 접속 사건에서 **평소와 다른 시각(0~5시·23시) + 처음 보는 네트워크(`unusual`) + 최근 300초 안 위험 사건(`risk_signal`) 합계 10건 이상**이 모두 맞을 때만 `step_up`(`step_up_required`)을 돌려줍니다. 엔진이 확인한 `stepUp`(`verified: true`, 나이 0~900초)이 있으면 같은 사건도 허용합니다. 지역(`region`)은 단독 근거로도 차단 근거로도 쓰지 않습니다. 출처가 `none`이거나 값이 없거나 형식이 틀리면 근거로 쓰지 않고 정상값으로 채우지도 않으며, 요청의 정해진 항목 밖 값(헤더·`geo`·`role` 등)은 읽지 않습니다. 기기 규칙이 먼저 적용됩니다.
- 자료 구역과 자원 ID(8단계): 자료는 두 구역으로 나뉩니다. 메모는 `note:<id>`, 강사 공지는 `notice:<id>`(목록은 `note:*`·`notice:*`)이며, 서버가 요청마다 만들어 응답 헤더 `X-Resource-Id`에 싣습니다. 기존 메모 주소와 화면은 그대로입니다.
- 강사 공지 API: `GET /api/notices`, `GET /api/notices/:id`는 로그인한 사용자 모두, `PUT /api/notices/:id`는 `public.instructors` 표에 **저장된** 사용자만 가능합니다. 요청 본문의 `role`·`owner_id`, 화면 메뉴, 토큰의 role 은 읽지 않으며, 심판 접속(`judge`)은 강사가 아닙니다. 권한이 없으면 공지가 있는지 알려 주기 전에 403(`not_instructor`)이고, 권한 조회가 실패하면 수정하지 않고 502입니다. 처음에는 강사가 한 명도 없어서 아무도 공지를 수정할 수 없습니다.
- 로그인 거부 기록: API가 401을 줄 때 서버 로그에 사유 분류(`no_authorization`, `not_bearer_jwt`, `verify_failed`와 발급자 종류, 심판 토큰이면 대상 주소)만 남깁니다. 토큰 원문·서명·사용자 ID는 남기지 않습니다.
- 자기 메모 API: 자기 목록은 명시적 경로 `GET /api/my/notes`로도 받을 수 있습니다(기존 `GET /api/notes`와 같은 소유자 필터 함수를 쓰고, 화면은 기존 주소 그대로). 메모 한 건 조회·수정·삭제는 저장된 `owner_id`가 확인된 사용자와 같을 때만 열립니다. 다른 사람·주인 없는 메모는 403(`not_owner`), 소유자 바꾸기는 403(`owner_change`)입니다. 거부할 때는 자원 ID와 사유만 서버 로그에 남기고 토큰·사용자 ID·메모 본문은 남기지 않습니다.
- 판정기 구역 규칙(8단계): 엔진이 확인한 `service`·`method`·`route`·실제 `path`가 읽기 구역 표와 정확히 맞을 때만 엽니다(`resource_zones`). 여는 구역은 자기 목록 `GET /api/my/notes`와 메모 한 건 읽기 `GET /api/notes/:id`(엔진 실습 모양 `GET /notes/:id` 포함)뿐이고 `service`는 `notes`여야 합니다. 계약에 자료 소유자·강사 역할이 없으므로 쓰기(메모 추가·수정·삭제, 공지 수정)는 모두 `write_not_allowed`로 거부하고, 모호한 목록 `GET /api/notes`·공지 경로·그 밖의 경로는 `route_not_allowed`로 거부합니다. 자료 ID 자리의 기능 이름(`export` 등)과 쿼리가 붙은 요청도 거부합니다. 판정기는 `subjectId`를 `owner_id`와 비교하지 않으며, 메모 한 건의 소유자와 강사 권한은 자료 API가 검증된 로그인과 저장된 값으로 다시 확인합니다. 그래서 엔진을 거치는 쓰기는 현재 막혀 있고(운영 엔진 연결은 미검증), 자기 메모 수정은 자료 API에서 그대로 됩니다.
- DB(8단계): `public.notices`(가상 공지 1건)와 `public.instructors`(비어 있음)를 `supabase/step8-notices.sql`로 만들었습니다. 둘 다 RLS가 켜져 있고 `anon`·`authenticated` 권한이 없으며 `service_role`만 읽고 씁니다.
- 탐지와 회수 제안(9단계, `src/detect.mjs`): 반 엔진이 검증해 넘긴 가상 사건 목록(`{ at, method, identity: { sub } }`)에서 **같은 `identity.sub`의 `GET`이 어느 10분 구간에서든 120건을 넘을 때만** `{ action: 'propose_revocation', reasonCode: 'burst_read', subject: <그 sub> }`를 돌려주고, 그 밖에는 `{ action: 'observe' }`입니다. 정확히 120건은 제안하지 않고, 10분 구간은 처음과 끝이 10분 이하인 묶음입니다. 사용자별로 따로 세며, `GET`이 아닌 요청·형식이 틀린 사건은 세지 않고, 순서가 뒤섞여도 같은 결과입니다. 여러 사용자가 넘으면 먼저 넘은 한 명만 제안합니다. 시각·요청 종류·`identity.sub` 세 값만 읽고 저장하거나 출력하지 않으며, 브라우저가 보낸 사용자 번호는 신원으로 읽지 않습니다. 이 파일은 아무것도 불러오지 않고 파일·네트워크를 쓰지 않으며, 접속 허용·거부 판정(`src/decider.mjs`)과 응답 형식은 건드리지 않았습니다. 지역이나 네트워크 항목은 이 계약의 사건에 없어서 쓰지 않았습니다.
- 9단계 한계(미실행): 이 탐지 함수는 **제안만** 돌려줍니다. 실제 회수·접속 차단·경과 시간 측정은 운영 반 엔진과 심판이 가상 사건으로 확인하는 부분이며, 이 저장소에는 회수 API가 없고 기기 권한을 바꾸지도 않습니다. `npm run detect:test`와 시험 통과는 실제 회수나 심판 통과가 아닙니다.
- 10단계 한 건 복구: 서비스 notes의 복구 경로는 POST /api/restore/:noteId입니다. (`aleph.config.json`의 `restoreRoute`도 같은 경로 모양입니다.) 로그인한 사용자가 **자기** 메모 한 건(`:noteId`)만 비공개 사전 사본에서 되돌립니다. 요청 본문·헤더·쿼리의 소유자·본문·해시·역할은 읽지 않고, 소유자는 검증된 로그인에서만 얻습니다. 복구는 DB 함수 `vault_restore_note`가 한 트랜잭션에서 하며, 사본을 **복구 직전에 매번 다시 읽어** 소유자와 ID·내용 SHA-256을 대조한 뒤에만 되돌립니다. 변조된 메모는 사본 내용으로 되돌리고(`updated`), 삭제된 메모는 같은 ID·소유자·내용으로 다시 만들며(`inserted`), 이미 같으면 아무것도 바꾸지 않습니다(`unchanged`). 응답은 `{ restored, action, id, ownerId, contentSha256 }`입니다. 사본이 없으면 404(`NO_BACKUP`), 다른 사람의 메모는 403(`not_owner`), 사본 검증이 어긋나면 409(`BACKUP_UNVERIFIED`)이고 이때는 아무것도 바꾸지 않습니다. 로그인이 없으면 401입니다. 다른 메모와 복구 기록은 건드리지 않습니다.
- 10단계 사본과 감사 기록(DB): `public.note_backups`는 메모를 **만들 때 처음 모습만** 봉인합니다(수정·삭제 때 덮어쓰지 않음, 트리거). `public.restore_audit`는 복구·거부를 한 줄씩 쌓는 기록입니다. 두 표 모두 RLS가 켜져 있고 `anon`·`authenticated` 권한이 없으며 `service_role`은 읽기만 합니다. 사본·기록은 고치거나 지울 수 없습니다(트리거). 이미 있던 메모 5건은 지금 모습 그대로 봉인했습니다(`supabase/step10-backup.sql`).
- 10단계 안전 정책 사본과 되돌리기: `backups/safe-policy.json`은 침해 전에 검증한 notes 서비스 정책 사본이고, 프로젝트·버전·정규화한 SHA-256(`src/policy-recovery.mjs`에 고정)을 매번 다시 읽어 검증합니다. 사본이 없거나 검증에 실패하면 중단합니다. `npm run policy:plan`(또는 읽기 전용 `GET /api/recovery-plan`)은 복원할 버전과 시험 정책(`policy/test-policy.json`)과의 차이만 보여 주고 아무것도 쓰지 않습니다. `npm run policy:restore -- <확인값>`은 방금 보여 준 계획의 확인값이 같을 때만 notes 정책을 사본 버전으로 되돌리고, 다른 서비스 규칙(`detect`)과 감사 이력은 그대로 두며 이력에 한 줄을 더합니다. 이것은 **시험 정책 사본**을 되돌리는 절차이고, 실제 운영 정책(판정기 코드)이나 운영 엔진 정책은 바꾸지 않습니다.
- 10단계 한계(미실행): 심판이 부르는 복구 경로의 실제 요청 모양(본문 항목 이름 등)은 확인하지 못했고, 로그인한 시험 계정 B로 배포 주소에서 변조·삭제 뒤 복구를 직접 보내 본 실측은 하지 않았습니다. 복구 동작은 DB에서 가상 B 메모로 시험하고 되돌렸으며(`supabase/step10-check.sql`), API 처리는 가짜 DB 함수로 시험했습니다. 판정기는 쓰기를 거부하므로 엔진을 거치는 복구 호출은 막혀 있습니다(운영 엔진 연결 미검증).
- 11단계 기기 승인 흐름(서버): 승인 여부는 서버가 정합니다(`src/protected-access.mjs`). 모든 보호 자료 API(`/api/notes`, `/api/notes/:id`, `/api/my/notes`, `/api/notices`, `/api/notices/:id`, `/api/restore/:noteId`)는 로그인 확인 **다음에** 서버의 승인 확인을 거치고, 승인되지 않았거나 확인할 수 없으면 자료에 접근하지 않습니다. 확인할 수 없으면 503(`device_verification_unavailable`), 승인 거부·대기이면 403(`device_not_approved`)입니다. 브라우저가 보낸 `approved`·`role`·`deviceRegistered`·헤더·쿼리·본문은 승인 근거로 읽지 않습니다. `GET /api/device/status`는 서버가 확인한 상태만 알려 주고, `POST /api/device/approval`은 승인 요청을 받아 줄 연결이 없으면 접수하지 않습니다(503). 로그인(`/api/auth/*`)과 공개 정책 사본(`/api/recovery-plan`)은 승인 확인 대상이 아닙니다.
- **11단계 한계(중요)**: 기기 키 보관·요청 서명 확인·기기 승인은 제공 엔진(ALEPH SDP)의 몫이고, 이 과정에서는 엔진 어댑터를 제공받지 못했습니다. 그래서 승인 어댑터가 연결돼 있지 않아 **지금 배포에서는 서버가 기기를 승인할 수 없고**, 로그인한 요청도 보호 자료 API가 503으로 막으며 `/vault.html`은 승인 전 상태로 남습니다(자료실 화면과 승인된 기기의 동작은 가짜 서버로 열어 시험했고 실제 엔진으로는 시험하지 못했습니다). 서명 없는 요청, 서명 뒤 경로·본문을 바꾼 요청은 어떤 요청도 승인되지 않으므로 자료를 돌려주지 않지만, 서명 검증 자체를 구현한 것은 아니며 실제 서명·승인된 기기 요청은 **미검증**입니다. 엔진이 연결되면 `src/protected-access.mjs`의 어댑터 한 곳만 채우면 됩니다. 자료실을 다시 쓰려면 이 단계의 승인 확인(`src/notes-common.mjs`의 `protectedAccess.check`)을 되돌리는 변경이 필요합니다(이전 커밋 `7ac8d6a` 참고).
- 12단계 탈환 작전실: `/operations.html`은 서버가 **방금 이 배포에 보낸 요청의 실제 응답**을 읽어 보여 줍니다(`GET /api/checks`). 화면의 문구나 색은 판정의 근거가 아니며, 확인하지 못한 것은 「미실행」「없음」으로 남깁니다. 메모 제목·본문·토큰·실명·기기 키는 읽지도 표시하지도 않습니다. 보여 주는 것: (1) 점검 요약(기대와 같음·기대와 다름·미실행 수), (2) 1~12단계 정상·금지 요청 실측표(단계·구분·요청과 응답 상태·기대·실제·결과·**요청 ID**·**확인 시각**; 요청 ID 는 응답의 `x-vercel-id` 끝 토큰으로 Vercel 기록의 Request ID 와 같아 서버 기록과 맞춰 볼 수 있습니다), (3) 판정기 규칙 이름과 가상 입력 점검 결과, (4) 탐지 사건(`local_fixture`, 가상 사건), (5) 회수 상태(연결 없음, 회수 수·경과 시간 null), (6) 복구 버전(안전 정책 사본 검증 결과, 메모 사본은 미실행), (7) 41종 시험표 요약과 목록. 점검 수치(점검·기대와 같음·기대와 다름·미실행)는 제출 묶음과 **같은 함수·같은 점검 목록**에서 나오며, 정상 화면·정책 확인은 따로 표로 보여 줍니다. 관측에 실패하면 이전 수치와 표를 모두 비우고 실패를 성공으로 표시하지 않습니다. 같은 서버가 15초 안에 다시 요청받으면 직전 관측을 자기 확인 시각과 함께 보여 줍니다(`cached`).
- 12단계 점검 방식(`src/attack-check.mjs`): `runAttackChecks(배포 주소 또는 설정)`이 배포에 실제 HTTP 요청을 보내 응답 상태로 `observed`를 만들고 `{ attackId, stage, expected, observed, result }`만 돌려줍니다(`result`는 `blocked`·`breached`·`not_run`, 20개 이하). **제출 묶음은 읽기 요청(GET·HEAD)만 보낼 수 있고 요청은 24건 이하여야 하므로**, 점검은 두 한도를 코드로 강제합니다(지금 8건, 모두 GET). **점검 하나(attackId)에는 요청을 하나만 보내고**, `observed`에는 심판이 확인할 수 있는 사실(`HTTP 상태`)만 적습니다(설명 문장은 `expected`에 둡니다). 요청이 없는 점검은 `not_run`입니다. 묶음에는 공격 점검만 넣고, `blocked`는 이 배포에 실제로 보낸 요청이 보호 장치의 거부 응답(401·403·405)을 받았을 때만 셉니다. 404(경로 없음)·5xx 는 공격이 보호 장치에 닿지 않은 것이라 `not_run`이고, 원본 자료 표 직접 조회(`s05-direct-table`)는 원본 API 가 이 배포 주소가 아니라서 보내지 않고 `not_run`으로 둡니다. 작전실의 41종 시험표는 계획표라서 막음 수(0종)와 실측표의 막음 수를 섞지 않습니다. 6~9단계 규칙 점검(`s06`~`s09`)은 가상 입력이라 실제 공격 실행이 아니므로 묶음에 넣지 않고 작전실 「판정기 규칙」에 `as_expected`·`unexpected`로만 보여 줍니다. 200 으로 열린 정상 요청(정적 자료 `s01-static-notes`, 승인 상태 `s11-device-status`, 정책 사본 `s10-policy-copy`, 화면 `s11-approval-screen`·`s11-vault-screen`·`s12-operations-screen`)은 막음이 아니므로 작전실에 「정상 요청 확인」으로 따로 보여 주며(결과 값은 `blocked`가 아닌 `as_expected`·`unexpected`) 점검 수치에 넣지 않습니다. 그래서 POST·PUT 같은 변경 요청(서명 없는 변경, 복구·승인 요청 호출)은 보내지 않고 GET 으로 확인할 수 있는 거부만 확인합니다. 요청을 보내지 못하거나 로그인이 필요해 보내지 않은 점검은 `not_run`이며 「막음」으로 세지 않습니다. 요청마다 `alephEvidence`에 사례(`caseId`)와 요청 이름(`requestKey`)을 연결하고 요청 헤더·URL 에는 넣지 않습니다. 이 파일은 아무것도 불러오지 않고 전역 `fetch`·`crypto`만 씁니다. 6~9단계 규칙 점검은 서버의 `GET /api/checks?case=<사례>`가 고정된 가상 입력으로 판정기·탐지 규칙을 실행한 응답(`ready`)을 읽으며(`src/rule-check.mjs`), 사례 이름은 고정 목록과만 비교하고 코드로 실행하지 않습니다. `ready`는 가상 조건이 맞았다는 뜻이지 실제 사용자 기기의 승인 상태가 아닙니다. 묶음(`npm run bundle`, `npm run check`)은 운영 측 현재 규칙대로 배포 주소를 넘기고 다섯 값과 `checkedAt`을 요구합니다.
- 41종 시험표(`data/attack-matrix.json`): 도감의 41종 이름·지역과 8~12단계 카드에서 옮긴 공격을 적은 **계획표**입니다. 1~7단계 24종은 단계와 공격 내용을 옮기지 않았고 「미확인」입니다. 이 저장소의 점검이 그 공격을 그대로 재현해 관측한 것만 `executed`로 바꿀 수 있으며 **지금은 0종**, 나머지 41종은 `not_run`입니다. 로그인한 시험 계정 B 가 필요한 공격, 회수된 신원의 재전송, 서명 변조는 이 저장소에서 재현하지 못했습니다. 포털 도감의 심판 기록(잡은 괴물 수)을 이 표의 실행 결과로 확대해 적지 않습니다.
- 공개 설정 사본: 빌드가 `/aleph.config.json`(스키마 `aleph.config.v1`: 단계·저장소·`originalApiUrl`·`restoreRoute`·`allowedRoutes` 객체 목록)을 만들어 배포합니다. 비밀값·로그인 발급자·심판 주소는 담지 않고 `aleph.config.json`의 값에서만 옮기며, 생성물이라 커밋하지 않습니다. 기존 `/aleph.json`은 그대로입니다.
- 12단계 한계(미실행): 로그인한 시험 계정 A·B 와 승인된 기기가 필요한 시험(타인 메모 조회·수정, 승인된 기기의 정상 요청), 회수 연결을 통한 재시도·재접속·이동, 서명 변조 시험, 메모 사본 개수 확인은 실행하지 못했습니다. 작전실의 점검은 로그인 없는 요청과 가상 규칙 입력만 보냅니다. 운영 엔진 연결·회수 수치·경과 시간은 **미연결**(null)입니다.
- 한계(미실행): 이 저장소의 `/api/*` 서버 함수는 아직 판정기를 부르지 않습니다. 8단계의 구역 규칙도 가상 요청으로만 시험했고, 로그인한 두 계정으로 배포 주소에서 남의 메모·공지 수정을 직접 보내 본 실측은 하지 않았습니다(시험 계정 로그인 정보가 없는 자동 점검은 `미실행`으로 남깁니다). 다시 로그인 전 실제 자료 차단과 새 로그인 뒤 허용은 제공 엔진이 새 로그인 시각을 검증하는 환경에서만 시험할 수 있어 **실측하지 않았습니다**. 여기서는 가상 요청으로 규칙만 시험했습니다.

### 다시 실행하는 방법

1. Vercel 프로젝트의 환경 변수에 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`(서버 전용), `SUPABASE_PUBLISHABLE_KEY`(공개 키, 서버 함수만 읽음)가 있어야 합니다. 값은 저장소에 넣지 않습니다.
2. Supabase 대시보드의 Authentication → Users에서 시험 계정 A·B를 만들고(Auto Confirm User 체크), 배포 주소에서 각각 로그인해 메모를 추가·수정·삭제합니다. A로 만든 메모는 B 화면에 보이지 않아야 합니다.
3. 거부 확인: `curl -i https://VERCEL_APP_URL/api/notes` → 401과 `{"error":"LOGIN_REQUIRED"}`
   로그인 경로 확인: `curl -i -X POST https://VERCEL_APP_URL/api/auth/login -H 'content-type: application/json' -d '{}'` → 400과 `INVALID_LOGIN`
4. DB 규칙: `supabase/step4-rls.sql`, `supabase/step5-revoke-direct.sql`, `supabase/step8-notices.sql` 순서로 Supabase SQL Editor에서 실행합니다. 샘플 메모의 소유자는 `owner_id`가 비어 있는 행을 시험 계정 A의 ID로 바꾸는 UPDATE로 연결했습니다. 적용 뒤 공개 키로 `/rest/v1/notes`를 직접 부르면 `permission denied`(HTTP 401)가 나와야 합니다.
5. 판정기 확인: `npm run decider:test`를 실행합니다.
   - `통과 · 등록 기기의 정상 요청` — `deviceRegistered: true` 요청이 `allow`·`approved`로 나와야 합니다.
   - `통과 · 미등록 기기의 가상 요청` — `deviceRegistered: false` 요청이 `deny`·`device_not_registered`로 나와야 합니다.
   - 마지막 줄 "이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다."가 보여야 합니다.
6. 7단계 확인: `npm run fixture:7`은 `정상 사건: allow`, `복합 이상 사건: step_up`을 보여 주고, `npm run decider:test`는 4건 모두 `통과`여야 합니다. 세부 경우(지역만 낯선 요청, 출처 불명, 확인 시각 만료 등)는 `node --test test/decider-step7.test.mjs`로 봅니다. 모두 가상 요청 연습이며 심판 판정이 아닙니다.
7. 8단계 확인: `node --test test/decider-step8.test.mjs test/access-step8.test.mjs`는 구역 규칙(자기 메모 허용, 공지 쓰기·알 수 없는 경로 거부)과 API 권한(A 자기 메모 허용, B의 A 메모 403, 일반 학생의 공지 수정 403)을 가짜 DB로 시험합니다. 배포 뒤 `curl -i https://VERCEL_APP_URL/api/notices` → 401과 `{"error":"LOGIN_REQUIRED"}`가 나와야 합니다. 강사를 지정하려면 Supabase SQL Editor에서 `insert into public.instructors (user_id) values ('<사용자 ID>');`를 직접 실행합니다.
8. 9단계 확인: `npm run detect:test`는 가상 사건 6건(정상 30건·120건은 관찰, 121건·200건은 `propose_revocation`, 사용자별 100건·10분 밖으로 흩어진 200건은 관찰)이 모두 `통과`여야 합니다. `node --test test/detect-step9.test.mjs`는 10분 경계, 뒤섞인 순서, 잘못된 사건, 한 명만 제안 같은 경우를 더 봅니다.
9. 10단계 복구 확인: 가상 시험 계정 B로 로그인해 새 가상 메모를 만든 뒤 (1) 그 메모를 수정해 변조한 다음 `POST /api/restore/<그 메모 id>`를 호출하면 처음 내용으로 돌아와야 하고, (2) 그 메모를 삭제한 다음 같은 경로를 호출하면 같은 ID·소유자·내용으로 다시 생겨야 합니다. 시험 계정 A가 같은 경로로 B의 메모 id를 호출하면 403이고 메모는 그대로여야 합니다. 로그인 없이 호출하면 401입니다(`curl -i -X POST https://VERCEL_APP_URL/api/restore/<메모 id>`). 정책 사본 확인은 `npm run policy:plan`입니다. DB 단독 시험은 `supabase/step10-check.sql`을 Supabase SQL Editor에서 실행합니다(끝에서 일부러 오류를 내 시험 행이 모두 되돌려지며 결과는 오류 메시지의 JSON으로 읽습니다).
10. 11단계 확인: 배포 주소의 `/`를 열면 「기기 승인 상태」「승인 요청」「자료실 열기」(꺼짐)와 오프라인 안내만 있고 로그인 폼·메모 목록이 없어야 합니다. 브라우저 개발자 도구에서 `<link rel="manifest">`와 `/manifest.webmanifest`(이름·시작 주소·표시 방식·아이콘)를 확인합니다. `curl -s https://VERCEL_APP_URL/api/device/status` → `approved:false`, `curl -i -X POST https://VERCEL_APP_URL/api/device/approval` → 503입니다. `/vault.html`도 승인 전에는 로그인 폼이 없고 개발자 도구 네트워크에 `/api/notes` 요청이 없어야 합니다. 승인 어댑터가 연결된 환경의 승인된 기기에서 기존 화면이 열리는지와 서명 변조 시험은 **미실행**입니다.
11. 12단계 확인: 배포 주소의 `/operations.html`을 열면 점검 요약·1~12단계 실측표(요청 ID·확인 시각 포함)·판정기 규칙·탐지(`local_fixture`)·회수(연결 없음)·복구 버전·41종 시험표가 보이고, 「새로 관측」을 누르면 새 확인 시각으로 바뀌어야 합니다. 표의 요청 ID 를 Vercel 프로젝트의 Logs 에서 찾으면 같은 요청(경로·상태 코드)이 있어야 합니다. `curl -s https://VERCEL_APP_URL/api/checks?case=s06-unregistered` → `ready:true`, `curl -s https://VERCEL_APP_URL/aleph.config.json` → 공개 설정 사본입니다. `npm run check`(= `npm run bundle`)는 실제 배포에 읽기 요청 8건을 보내 다섯 값(`attackId·stage·expected·observed·result`)을 만들며 `not_run`은 미실행 항목입니다. 시험표의 `executed`는 0종이므로 시험표를 실행 결과로 읽지 않습니다.
12. 복구 뒤 1~9단계 다시 확인하는 순서(실행하지 않은 것은 **미실행**으로 남기고 결과를 꾸미지 않습니다):
    1. `npm run policy:plan` — 차이 0개이거나, 복원 뒤에는 `바뀔 항목 0개`여야 합니다. 시험 정책이 바뀌었으면 보여 준 확인값으로 `npm run policy:restore -- <확인값>`.
    2. `npm run decider:test` → `npm run fixture:7` → `npm run detect:test` — 6·7·9단계 가상 요청·사건(각각 심판 판정이 아닙니다).
    3. `node --test test/*.test.mjs` — 8·10단계 구역·권한·복구·정책 시험을 포함한 전체 시험.
    4. `npm run xdr:run -- brute-force` → `npm run xdr:run -- web-injection` — 보너스 결과 파일이 그대로인지 `git status`로 확인.
    5. 배포 뒤 로그인 없이 `curl -i https://VERCEL_APP_URL/api/notes`, `/api/my/notes`, `/api/notices`, `POST /api/restore/<id>` → 모두 401, `/data.json`은 메모 없음.
    6. 11단계부터 보호 API는 승인 확인이 먼저라 로그인한 시험 계정 A·B 실측은 승인 어댑터 연결 전에는 503이 나옵니다(미실행): 로그인한 시험 계정 A·B 실측(남의 메모 조회·수정·목록 거부, 공지 수정 거부, 자기 메모 정상 사용): 시험 계정 로그인 정보가 없는 자동 점검에서는 **미실행**입니다.
    7. `npm run bundle` — 직접 점검 결과와 미실행 항목을 읽습니다.
13. 제출 묶음: 변경을 모두 커밋한 뒤 `ALEPH_PUBLIC_KEY=<공개 키> npm run bundle`을 실행합니다. 공개 키는 원본 자료 주소를 직접 읽어 보는 점검에만 쓰이고 어디에도 기록되지 않으며, 주지 않으면 그 점검은 "미실행"으로 남습니다. 결과는 `artifacts/submission.json`에 담기며 커밋하지 않습니다.

## 검사한 커밋에서 재현하기

모든 절차는 **검사한 커밋**을 기준으로 합니다. 검사한 커밋은 제출 묶음(`artifacts/submission.json`, 커밋하지 않음)의 `commit` 값이고, 배포의 `/aleph.json`이 알려 주는 `commit`과 같아야 합니다.

### 학생이 만든 것과 제공 엔진의 출처

| 출처 | 들어 있는 것 |
|---|---|
| 학생이 만든 것 | 판정기(`src/decider.mjs`), 탐지 규칙(`src/detect.mjs`), 접속 앱 화면(`public/index.html`·`manifest.webmanifest`·`vault.html`·`vault-app.js`), 탈환 작전실(`public/operations.html`, `api/checks`, `src/operations.mjs`), 자료실 서버 함수(`api/`), 백업·복구(SQL 과 `api/restore`, `src/policy-recovery.mjs`), 점검 코드(`src/attack-check.mjs`), 보너스 XDR 판정(`xdr/*/decide.mjs`) |
| 제공 엔진 | **ALEPH SDP 엔진**(수업 운영 측이 제공): 기기 등록·기기 키 보관·로그인과 기기 결합·요청 서명 확인·판정기 호출과 집행·접속 회수·감사 기록 보관을 맡습니다. 이 저장소에는 엔진 코드·키·바이너리·설치 명령을 넣지 않았고, 엔진은 이 과정에서 연결되지 않았습니다. |
| 수업 제공 시작 틀 | `scripts/bundle.mjs`·`scripts/build-public.mjs`·`scripts/deployment-identity.mjs`·`src/verify-login.mjs` 등(운영 측 규칙에 맞게 일부만 고침) |

### 1. 설치

1. 이 공개 저장소를 clone 하고 검사한 커밋으로 `git checkout <검사한 커밋>` 합니다(Node.js 22 이상).
2. `npm ci`로 패키지를 설치합니다(`@supabase/supabase-js`, `jose`).
3. 서버 비밀 설정은 Vercel 프로젝트의 환경 변수에만 둡니다(`SUPABASE_URL`, `SUPABASE_SECRET_KEY`, `SUPABASE_PUBLISHABLE_KEY`). 값은 이 저장소·답변·로그에 넣지 않으며 포장하지 않습니다.
4. 새 DB 라면 학습 전용 Supabase 프로젝트에서만 `supabase/` 의 SQL 을 `step4-rls`, `step5-revoke-direct`, `step8-notices`, `step10-backup` 순서로 실행합니다. 현재 DB 는 초기화할 필요가 없고 지우지 않습니다.

### 2. 실행

1. 같은 커밋을 Vercel 에 배포합니다(저장소를 연결한 프로젝트에 push). 빌드는 `npm run build`(공개 정적 파일과 `/aleph.json`·`/aleph.config.json` 생성)입니다.
2. 배포의 `/aleph.json`의 `repoUrl`·`commit`이 실제 원격과 검사한 커밋에 맞는지 대조합니다.
3. 화면: `/`(접속 화면, 기기 승인 상태)와 `/operations.html`(탈환 작전실)을 엽니다. 서버 승인 어댑터가 연결돼 있지 않으면 보호 자료 API 는 로그인한 요청도 503 으로 막고 `/vault.html`은 승인 전 상태로 남습니다.
4. 시험: `npm test`(= `node --test test/*.test.mjs`), `npm run decider:test`, `npm run fixture:7`, `npm run detect:test`, `npm run policy:plan`. 모두 가상 요청·사건 연습이며 심판 통과의 증거가 아닙니다.
5. 점검: 변경을 모두 커밋한 뒤 커밋하지 않는 `bundle-notes.json`에 실제로 구현하고 확인한 내용을 적고 `npm run bundle`(또는 `npm run check`)을 실행합니다. `artifacts/submission.json`은 실제 HEAD·원격과 새 실측으로 만들어지며 커밋하지 않습니다.

### 3. 중지

1. Vercel 프로젝트에서 현재 배포를 내리거나(Instant Rollback, 프로젝트 일시 중지) 환경 변수를 비활성화해 서버 함수가 자료에 접근하지 못하게 합니다.
2. 제공 엔진이 연결돼 있다면 엔진 쪽에서 이 자료실의 허용 경로를 끕니다. 이 저장소에서 엔진을 끄는 방법은 제공하지 않습니다.
3. DB·사본·복구 기록·감사 자료는 지우지 않습니다.

### 4. 복구

1. `git status`와 `git diff`로 변경을 확인하고 보존할 내용을 남깁니다. `git reset --hard`는 쓰지 않습니다.
2. 검사한 커밋을 별도로 checkout 해 같은 방식으로 다시 배포합니다.
3. 메모 한 건 복구: 로그인한 본인의 메모 ID 하나만 `POST /api/restore/:noteId`로 지정합니다(서비스 notes). 사본 소유자·ID·내용 해시를 대조하고 다른 메모·감사 기록은 건드리지 않습니다.
4. 정책 복구: `npm run policy:plan`으로 복원할 버전과 바뀔 항목을 먼저 보고, 확인값이 맞을 때만 `npm run policy:restore -- <확인값>`을 실행합니다(시험 정책만, 운영 정책은 건드리지 않음).
5. 복구 뒤 위 "복구 뒤 1~9단계 다시 확인하는 순서"와 `npm run bundle`, 작전실의 새 관측을 다시 실행하고 **실행하지 않은 시험은 미실행으로 남깁니다**.

## 가상 메모 노출 확인 절차

### 1. 현재 GitHub 저장소 파일 검색

```bash
# 저장소 루트에서 실행
git grep -n "실습용 가상"
```

현재 브랜치 추적 파일에서 결과가 없어야 합니다.  
`supabase/notes.sql`의 INSERT 값은 DB 이관 기록이므로 여기서 검출돼도 정상입니다.

> **주의**: `git grep`은 현재 체크아웃된 파일만 검사합니다. 과거 커밋에는 메모 문장이 남아 있으며, 옛 공개 커밋이 존재하는 한 과거 노출은 해소됐다고 볼 수 없습니다.

### 2. 현재 배포 파일 확인

```bash
# 배포 후 실행 (VERCEL_APP_URL을 실제 주소로 교체)
curl -s https://VERCEL_APP_URL/data.json | grep -c "실습용 가상"
# 결과: 0

curl -s https://VERCEL_APP_URL/api/notes
# 결과: {"error":"LOGIN_REQUIRED"}
# → 로그인 토큰 없이는 메모가 응답에 포함되지 않습니다 (HTTP 401)
```

`/data.json`과 `/api/notes` 어느 쪽에서도 로그인 없이 읽을 수 있는 메모가 없어야 합니다.  
Vercel 배포 이력에 이전 버전이 남아 있으면 옛 `/data.json`도 접근 가능할 수 있습니다.

### 3. 확인 결과 기록란

| 확인 항목 | 결과 | 날짜 |
|---|---|---|
| `git grep "실습용 가상"` (현재 파일) | `supabase/notes.sql`(DB 이관 기록)과 이 README의 설명 문구만 검출 | 2026-10-07 |
| `/data.json` 메모 포함 여부 | 없음 (HTTP 200, 메모·확인 표시 없음) | 2026-10-07 |
| `/api/notes` 인증 없이 반환 여부 | 반환 안 됨 (HTTP 401) | 2026-10-07 |
| 공개용 `anon` 키로 DB 데이터 주소 직접 읽기 | 권한 없음 (HTTP 401, `42501`), 메모 행 0건 | 2026-10-07 |
| B로 로그인한 화면에서 A의 메모가 보이는가 | 안 보임 (B의 메모 1건만 보임) | 2026-10-07 |
| B가 A의 메모 id로 조회·수정·삭제·가로채기 (API) | 모두 403, A의 메모는 그대로 | 2026-10-07 |
| 로그인 토큰으로 DB 직접 접근 (4단계 시점, RLS) | 본인 행만 조회·수정·삭제, 남의 행은 0건, 남의 소유로 INSERT·UPDATE는 `42501` 오류 | 2026-10-07 |
| 8단계 새 표 권한 (`notices`, `instructors`) | `anon`·`authenticated`·`PUBLIC` 권한 없음, `service_role`만 보유, RLS 켜짐, 공지 1건·강사 0명, 메모 5건 그대로 (`role_table_grants`·`pg_class`로 확인) | 2026-10-13 |
| 10단계 새 표·함수 권한 (`note_backups`, `restore_audit`, `vault_*`) | `anon`·`authenticated`·`PUBLIC` 권한 없음, `service_role`은 표 읽기만·복구 함수 실행만, RLS 켜짐, 사본 5건이 현재 메모 5건과 일치, 복구 기록 0건 (`role_table_grants`·`pg_class`·`aclexplode`로 확인) | 2026-10-13 |
| 10단계 DB 시험 (가상 B 메모, `supabase/step10-check.sql`) | 변조·삭제 뒤 복구 일치(ID·소유자·제목·내용 해시), 다른 사용자 거부, 사본 없음 거부, 한 건만 복구, 사본 고치기·기록 지우기 차단, 사본 해시 불일치 시 복구 중단. 시험 행은 모두 되돌려져 메모 5건·사본 5건·기록 0건 그대로 | 2026-10-13 |
| 5단계 권한 회수 | `anon`·`authenticated`는 `public.notes` 권한 없음, `service_role`만 보유 (`role_table_grants`·`has_table_privilege`로 확인) | 2026-10-07 |
| 첫 화면 코드의 키 모양 문자열 | 0개 (HTTP 200), Supabase 주소·외부 라이브러리 없음 | 2026-10-07 |
| `/aleph.json`의 허용 경로 | 8개 (HTTP 200) | 2026-10-07 |
| `/aleph.json`의 원본 자료 주소 (`originalApiUrl`) | 5단계 심판이 배포본에서 찾지 못해(`S05_ORIGINAL_URL_MISSING`) 빌드가 이 값을 싣도록 고침. 단위 시험과 빌드 흉내로 확인했고, 배포본 확인은 제출 번들의 `aleph_json_original_api_url` 점검에 기록 | 2026-10-07 |
| 새 로그인 경로 `/api/auth/*` (실제 계정 A·B로 로그인) | 로그인하면 화면에 본인 메모만 표시. 만료시킨 토큰은 화면이 알아서 갱신(갱신 토큰 교체, 새 토큰 약 1시간). 로그아웃하면 브라우저 세션이 지워지고 이전 갱신 토큰은 401 `SESSION_EXPIRED`. 빈 요청 400·틀린 정보 401·GET 405·엉터리 갱신 토큰 401 | 2026-10-07 |
| A·B가 서로의 메모에 접근 (API, 5단계 재확인) | 조회·수정·삭제·가로채기·소유자 변경 모두 403, 각자 자기 메모의 추가·수정·삭제는 정상, 시험 뒤 DB 5건 그대로 | 2026-10-07 |
| 로그인 토큰 + 공개 키로 원본 자료 주소 직접 접근 (A·B 모두, 5단계) | 조회·수정·삭제·추가 모두 `403`(`42501`, permission denied). 토큰 없이 공개 키만 쓰면 `401` | 2026-10-07 |
| 과거 커밋·배포 노출 해소 여부 | **미해소** (과거 기록 잔존) | — |

## 현재 알려진 약점

| 약점 | 경로 | 상태 |
|---|---|---|
| `/api/notes` 인증 없음 | `api/notes.js`, `api/notes/[id].js` | 3단계에서 차단 (토큰이 없으면 401) |
| 소유자 검사 없음 | `api/notes/[id].js` | 4단계에서 차단 (다른 사용자·주인 없는 메모는 403) |
| DB 권한이 넓음 (`anon`·`authenticated`에 테이블 권한 전체, RLS 정책 없음) | Supabase `public.notes` | 4단계에서 정책 추가, 5단계에서 `anon`·`authenticated` 직접 권한 회수 |
| 기존 샘플 메모 4건에 `owner_id` 없음 | Supabase `public.notes` | 4단계에서 해결 (시험 계정 A 소유로 연결) |
| 로그인 키가 화면 코드에 있음 (공개 키라도 화면에서 DB 주소로 직접 접근 가능했음) | `public/index.html` | 5단계에서 해결 (로그인을 서버 함수로 옮기고 화면에서 키·주소 제거) |
| 로그인 대입 시도가 우리 서버를 거침 | `/api/auth/login` | 미수정 (속도 제한은 Supabase 기본값에만 의존) |

메모는 서버 함수가 서버 전용 키로만 읽고 쓰며, 그 앞에서 소유자를 직접 비교합니다. DB의 권한 회수와 RLS 정책은 그 길이 우회되지 않게 하는 안전장치입니다. 남은 것: Supabase Auth의 "유출 비밀번호 차단"이 꺼져 있습니다(보안 점검 경고 1건, 메모 테이블과는 무관). 시작 틀이 `/aleph.json`에 기록하는 `sampleMarker`(시드 표식 이름)는 그대로 두었습니다. 5단계 심판이 이 파일도 공개 파일 검색에 넣으면 걸릴 수 있어서, 제출 결과의 실패 코드로 확인합니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
