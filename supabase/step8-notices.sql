-- 8단계: 강사 공지(notices)와 강사 권한(instructors)
-- 둘 다 서버 함수(service_role)만 읽고 씁니다. 화면·공개 키·로그인 토큰으로는 직접 접근할 수 없습니다.
-- 강사 권한은 이 표에 저장된 사용자 ID만 가집니다. 요청 본문·화면 메뉴·토큰의 role 은 믿지 않습니다.

create table if not exists public.notices (
  id          uuid        primary key default gen_random_uuid(),
  title       text        not null,
  content     text        not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.instructors (
  user_id     uuid        primary key,
  created_at  timestamptz not null default now()
);

alter table public.notices enable row level security;
alter table public.instructors enable row level security;

revoke all on public.notices from public, anon, authenticated;
revoke all on public.instructors from public, anon, authenticated;
grant select, insert, update, delete on public.notices to service_role;
grant select, insert, update, delete on public.instructors to service_role;

-- 학습용 가상 공지 (실제 공지 아님). 이미 공지가 있으면 넣지 않습니다.
insert into public.notices (title, content)
select '수업 안내 (가상)', '가상 강사 공지입니다. 실제 공지가 아닙니다.'
where not exists (select 1 from public.notices);

-- 강사 지정(필요할 때만, SQL Editor에서 직접): 사용자 ID 는 Authentication → Users 에서 복사합니다.
--   insert into public.instructors (user_id) values ('<강사로 지정할 사용자 ID>');
-- 처음에는 강사가 한 명도 없으므로 아무도 공지를 수정할 수 없습니다.
