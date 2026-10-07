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

## 현재 작동하는 기능 (5단계)

- `/`: 이메일·비밀번호 로그인과 로그아웃. 로그인하면 본인 계정으로 가상 메모를 추가·수정·삭제하는 화면이 보입니다. 화면은 서버 함수(`/api/*`)만 부르고, 화면 코드에는 Supabase 주소·공개 키·외부 라이브러리가 없습니다.
- `POST /api/auth/login`·`/refresh`·`/logout`: 서버가 Supabase Auth를 공개 키(서버 환경 변수 `SUPABASE_PUBLISHABLE_KEY`)로 대신 부르고, 화면에는 로그인 토큰·갱신 토큰·만료 시각·사용자 ID·이메일만 돌려줍니다. 틀린 정보는 401(`LOGIN_FAILED`), 공개 키 설정 문제는 503(`AUTH_MISCONFIGURED`)입니다. 화면은 토큰이 만료되면 알아서 갱신하고, 갱신이 안 되면 로그아웃 상태로 돌아갑니다.
- `GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id`: 서버가 요청의 로그인 토큰을 `src/verify-login.mjs`로 확인합니다. 토큰이 없거나 틀리면 자료 없이 401입니다.
- 소유자 검사: 서버가 확인한 사용자 ID와 DB의 `owner_id`를 비교해, 다른 사용자(또는 주인 없는) 메모의 조회·수정·삭제는 403으로 거부합니다. 없는 id는 404입니다. 목록은 본인 메모만 돌려주고, 추가할 때는 확인된 ID를 `owner_id`로 저장합니다. 요청에 실려 온 `owner_id`·사용자 ID·역할은 믿지 않으며, 소유자를 바꾸려는 수정은 403입니다.
- `/data.json`: 메모 없이 `{"notes":[]}`만 공개합니다. `/aleph.json`: 빌드가 단계·커밋·주소와 허용 경로(`allowedRoutes` 8개)를 기록합니다.
- DB 권한: `public.notes`는 RLS가 켜져 있고 `anon`·`authenticated`의 직접 권한을 모두 회수했습니다(`supabase/step4-rls.sql`, `supabase/step5-revoke-direct.sql`). 정책 4개(`auth.uid() = owner_id`)는 권한이 다시 열릴 때를 대비한 안전장치로 남겼습니다. 메모는 서버 함수가 서버 전용 키로만 읽고 쓰며, 원본 자료 주소는 `aleph.config.json`의 `originalApiUrl`에 적었습니다. 기존 샘플 메모 4건은 시험 계정 A 소유로 연결했고, 시험 계정 B 소유의 시험 메모가 1건 있습니다.

### 다시 실행하는 방법

1. Vercel 프로젝트의 환경 변수에 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`(서버 전용), `SUPABASE_PUBLISHABLE_KEY`(공개 키, 서버 함수만 읽음)가 있어야 합니다. 값은 저장소에 넣지 않습니다.
2. Supabase 대시보드의 Authentication → Users에서 시험 계정 A·B를 만들고(Auto Confirm User 체크), 배포 주소에서 각각 로그인해 메모를 추가·수정·삭제합니다. A로 만든 메모는 B 화면에 보이지 않아야 합니다.
3. 거부 확인: `curl -i https://VERCEL_APP_URL/api/notes` → 401과 `{"error":"LOGIN_REQUIRED"}`
   로그인 경로 확인: `curl -i -X POST https://VERCEL_APP_URL/api/auth/login -H 'content-type: application/json' -d '{}'` → 400과 `INVALID_LOGIN`
4. DB 규칙: `supabase/step4-rls.sql`, `supabase/step5-revoke-direct.sql` 순서로 Supabase SQL Editor에서 실행합니다. 샘플 메모의 소유자는 `owner_id`가 비어 있는 행을 시험 계정 A의 ID로 바꾸는 UPDATE로 연결했습니다. 적용 뒤 공개 키로 `/rest/v1/notes`를 직접 부르면 `permission denied`(HTTP 401)가 나와야 합니다.
5. 제출 묶음: 변경을 모두 커밋한 뒤 `ALEPH_PUBLIC_KEY=<공개 키> npm run bundle`을 실행합니다. 공개 키는 원본 자료 주소를 직접 읽어 보는 점검에만 쓰이고 어디에도 기록되지 않으며, 주지 않으면 그 점검은 "미실행"으로 남습니다. 결과는 `artifacts/submission.json`에 담기며 커밋하지 않습니다.

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
| 5단계 권한 회수 | `anon`·`authenticated`는 `public.notes` 권한 없음, `service_role`만 보유 (`role_table_grants`·`has_table_privilege`로 확인) | 2026-10-07 |
| 첫 화면 코드의 키 모양 문자열 | 0개 (HTTP 200), Supabase 주소·외부 라이브러리 없음 | 2026-10-07 |
| `/aleph.json`의 허용 경로 | 8개 (HTTP 200) | 2026-10-07 |
| 새 로그인 경로 `/api/auth/*` | 빈 요청 400, 틀린 정보 401, GET 405, 엉터리 갱신 토큰 401 (운영 서버 응답으로 확인). 실제 계정 로그인은 A·B로 확인하는 대로 기록 | 2026-10-07 |
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
