-- Step 4: public.notes 에만 RLS와 최소 권한을 적용한 기록입니다.
-- Supabase 마이그레이션 step4_notes_rls_least_privilege 로 적용했습니다.
-- 우리 API는 서버 전용 키(service_role)로 접근하므로 이 규칙과 상관없이 동작하고, 소유자 비교는 API가 직접 합니다.
-- 이 규칙은 anon 키나 로그인 토큰으로 DB 데이터 주소를 직접 부르는 길을 막습니다.

alter table public.notes enable row level security;

revoke all on table public.notes from public, anon, authenticated;
grant select, insert, update, delete on table public.notes to authenticated;

drop policy if exists notes_select_own on public.notes;
drop policy if exists notes_insert_own on public.notes;
drop policy if exists notes_update_own on public.notes;
drop policy if exists notes_delete_own on public.notes;

create policy notes_select_own on public.notes for select to authenticated
  using ((select auth.uid()) = owner_id);
create policy notes_insert_own on public.notes for insert to authenticated
  with check ((select auth.uid()) = owner_id);
create policy notes_update_own on public.notes for update to authenticated
  using ((select auth.uid()) = owner_id)
  with check ((select auth.uid()) = owner_id);
create policy notes_delete_own on public.notes for delete to authenticated
  using ((select auth.uid()) = owner_id);
