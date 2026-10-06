-- Step 2: notes table
-- owner_id 칸은 미래 소유권 연결용으로 미리 둠. auth.users FK 없음 (의도적).
-- RLS ON: 일치하는 정책이 없으면 모든 역할의 접근이 기본 차단됨.

create table if not exists notes (
  id          uuid        primary key default gen_random_uuid(),
  owner_id    uuid,
  title       text        not null,
  content     text        not null,
  created_at  timestamptz not null default now()
);

alter table notes enable row level security;

-- anon·authenticated에 읽기 정책 없음 → SELECT 불가
-- (필요 시 service_role 또는 별도 정책으로만 접근)

-- 학습용 가상 메모 (실제 학생 자료 아님)
insert into notes (title, content) values
  ('과제',         '실습용 가상 과제 기록'),
  ('포트폴리오',   '실습용 가상 포트폴리오 기록'),
  ('아침 리추얼',  '실습용 가상 리추얼 기록'),
  ('훈련 행정 자료', '실습용 가상 행정 기록');
