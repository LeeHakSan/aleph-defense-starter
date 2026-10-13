-- 10단계 DB 시험: 가상 B 메모를 새로 만들어 변조·삭제 뒤 한 건 복구, 타인 거부, 사본 고치기 거부를 확인합니다.
-- 마지막에 일부러 오류를 내서 이 시험이 만든 모든 행(메모·사본·복구 기록)이 되돌려집니다. 기존 메모는 건드리지 않습니다.
-- 결과는 오류 메시지의 JSON 으로 읽습니다(STEP10_CHECK_RESULT).
do $$
declare
  b_user  uuid := gen_random_uuid();
  other   uuid := gen_random_uuid();
  n1      uuid := gen_random_uuid();
  n2      uuid := gen_random_uuid();
  r       jsonb;
  out     jsonb := '{}'::jsonb;
  before_count int := (select count(*) from public.notes);
  other_note_before text;
  caught  text;
begin
  insert into public.notes (id, owner_id, title, content) values (n1, b_user, '가상 B 메모', '원본 가상 내용');
  insert into public.notes (id, owner_id, title, content) values (n2, b_user, '다른 가상 메모', '건드리면 안 되는 내용');
  other_note_before := (select content from public.notes where id = n2);
  out := out || jsonb_build_object('sealed_on_insert', (select count(*) from public.note_backups where note_id in (n1, n2)) = 2);

  -- 1) 변조 뒤 복구
  update public.notes set title = '변조 제목', content = '변조된 내용' where id = n1;
  r := public.vault_restore_note(n1, b_user);
  out := out || jsonb_build_object('tamper_status', r->>'status', 'tamper_action', r->>'action',
    'tamper_content_back', (select content from public.notes where id = n1) = '원본 가상 내용',
    'tamper_title_back', (select title from public.notes where id = n1) = '가상 B 메모',
    'tamper_hash_matches_original', r->>'contentSha256' = public.vault_content_sha256('원본 가상 내용'));

  -- 2) 삭제 뒤 복구(같은 id·소유자·내용)
  delete from public.notes where id = n1;
  r := public.vault_restore_note(n1, b_user);
  out := out || jsonb_build_object('delete_status', r->>'status', 'delete_action', r->>'action',
    'delete_same_id_owner_content', exists (select 1 from public.notes where id = n1 and owner_id = b_user and content = '원본 가상 내용' and title = '가상 B 메모'));

  -- 3) 이미 같으면 아무것도 바꾸지 않음
  r := public.vault_restore_note(n1, b_user);
  out := out || jsonb_build_object('again_action', r->>'action');

  -- 4) 다른 사용자는 거부되고 메모는 그대로
  update public.notes set content = '변조 2' where id = n1;
  r := public.vault_restore_note(n1, other);
  out := out || jsonb_build_object('other_user_status', r->>'status',
    'other_user_left_tamper', (select content from public.notes where id = n1) = '변조 2');

  -- 5) 사본이 없는 메모
  r := public.vault_restore_note(gen_random_uuid(), b_user);
  out := out || jsonb_build_object('no_backup_status', r->>'status');

  -- 6) 한 건만 복구하고 다른 메모는 그대로
  update public.notes set content = '다른 메모도 변조' where id = n2;
  r := public.vault_restore_note(n1, b_user);
  out := out || jsonb_build_object('only_target_restored', (select content from public.notes where id = n1) = '원본 가상 내용',
    'other_note_untouched_by_restore', (select content from public.notes where id = n2) = '다른 메모도 변조');

  -- 7) 사본·복구 기록은 고치거나 지울 수 없음
  begin
    update public.note_backups set content = '사본 변조' where note_id = n1;
    caught := 'update_allowed';
  exception when others then caught := sqlerrm;
  end;
  out := out || jsonb_build_object('backup_update_blocked', caught = 'note_backups_are_append_only');
  begin
    delete from public.restore_audit where note_id = n1;
    caught := 'delete_allowed';
  exception when others then caught := sqlerrm;
  end;
  out := out || jsonb_build_object('audit_delete_blocked', caught = 'note_backups_are_append_only');

  -- 8) 복구 직전 재검증: 사본의 해시가 어긋나면 복구하지 않음(트리거를 잠시 끄고 고장 낸 사본을 흉내)
  alter table public.note_backups disable trigger vault_backup_no_change;
  update public.note_backups set content = '몰래 바뀐 사본' where note_id = n1;
  alter table public.note_backups enable trigger vault_backup_no_change;
  update public.notes set content = '변조 3' where id = n1;
  r := public.vault_restore_note(n1, b_user);
  out := out || jsonb_build_object('corrupt_backup_status', r->>'status',
    'corrupt_backup_left_note', (select content from public.notes where id = n1) = '변조 3');

  out := out || jsonb_build_object('audit_rows_for_test', (select count(*) from public.restore_audit where note_id in (n1, n2)),
    'audit_actions', (select jsonb_agg(action order by id) from public.restore_audit where note_id = n1));
  out := out || jsonb_build_object('notes_count_during', (select count(*) from public.notes), 'notes_count_before', before_count);

  raise exception 'STEP10_CHECK_RESULT %', out::text;
end $$;
