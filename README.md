# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 현재 작동하는 기능 (3단계)

- `/`: 이메일·비밀번호 로그인과 로그아웃(Supabase Auth). 로그인하면 본인 계정으로 가상 메모를 추가·수정·삭제하는 화면이 보입니다.
- `GET·POST /api/notes`, `GET·PUT·DELETE /api/notes/:id`: 서버가 요청의 로그인 토큰을 `src/verify-login.mjs`로 확인합니다. 토큰이 없거나 틀리면 자료 없이 401입니다. 메모를 추가할 때 서버가 확인한 사용자 ID를 `owner_id`로 저장하고, 요청에 실려 온 사용자 ID·역할은 읽지 않습니다. 목록은 로그인한 사용자 본인의 메모만 돌려줍니다.
- `/data.json`: 메모 없이 `{"notes":[]}`만 공개합니다.
- 아직 막지 못한 것: 로그인한 사용자는 다른 사람 메모의 id로도 읽기·수정·삭제를 할 수 있습니다. 소유자 검사는 4단계에서 붙입니다.

### 다시 실행하는 방법

1. Vercel 프로젝트의 환경 변수에 `SUPABASE_URL`, `SUPABASE_SECRET_KEY`가 있어야 합니다. 값은 저장소에 넣지 않습니다.
2. Supabase 대시보드의 Authentication → Users에서 시험 계정을 만들고, 배포 주소에서 로그인해 메모를 추가·수정·삭제합니다.
3. 거부 확인: `curl -i https://VERCEL_APP_URL/api/notes` → 401과 `{"error":"LOGIN_REQUIRED"}`
4. 제출 묶음: 변경을 모두 커밋한 뒤 `npm run bundle`을 실행합니다. 결과는 `artifacts/submission.json`에 담기며 커밋하지 않습니다.

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
| 과거 커밋·배포 노출 해소 여부 | **미해소** (과거 기록 잔존) | — |

## 현재 알려진 약점

| 약점 | 경로 | 상태 |
|---|---|---|
| 소유자 검사 없음 | `api/notes/[id].js` | 미수정 (4단계에서 차단 예정) |
| `/api/notes` 인증 없음 | `api/notes.js`, `api/notes/[id].js` | 3단계에서 차단 (토큰이 없으면 401) |

로그인한 사용자는 다른 사용자의 메모 id를 알면 `GET·PUT·DELETE /api/notes/:id`로 그 메모를 읽고 고치고 지울 수 있습니다. 목록(`GET /api/notes`)은 로그인한 사용자 본인의 메모만 돌려줍니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
