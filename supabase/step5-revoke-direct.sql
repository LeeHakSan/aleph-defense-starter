-- Step 5: 브라우저·공개 키·로그인 토큰으로 DB 데이터 주소(/rest/v1/notes)를 직접 부르는 권한을 모두 거둔 기록입니다.
-- Supabase 마이그레이션 step5_notes_revoke_direct_access 로 적용했습니다. public.notes 에만 적용하고 다른 테이블은 건드리지 않습니다.
-- 이제 메모는 서버 함수(service_role)만 읽고 쓰며, step4-rls.sql 의 정책 4개는 권한이 다시 열릴 때를 대비한 안전장치로 남깁니다.

alter table public.notes enable row level security;

revoke all on table public.notes from public, anon, authenticated;

-- 적용 전후 확인 (적용 전: anon·authenticated 모두 조회·추가·수정·삭제 가능, 적용 후: 모두 불가, service_role 은 그대로)
-- select grantee, string_agg(privilege_type, ',' order by privilege_type)
--   from information_schema.role_table_grants
--  where table_schema = 'public' and table_name = 'notes'
--    and grantee in ('anon', 'authenticated', 'service_role', 'PUBLIC')
--  group by grantee;
-- select has_table_privilege('anon', 'public.notes', 'select'),
--        has_table_privilege('authenticated', 'public.notes', 'select');
