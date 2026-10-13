-- 10단계: 비공개 메모 사본과 한 건 복구
-- 메모를 만들 때 처음 모습만 사본으로 봉인합니다(트리거). 수정·삭제 때는 사본을 덮어쓰지 않습니다.
-- 사본·복구 기록은 서버 함수(service_role)만 읽을 수 있고, 사본은 누구도 고치거나 지울 수 없습니다.
-- 복구는 vault_restore_note 한 건씩만 하며, 사본의 소유자·해시를 다시 대조한 뒤에만 되돌립니다.

create table if not exists public.note_backups (
  note_id          uuid        primary key,
  owner_id         uuid        not null,
  title            text        not null,
  content          text        not null,
  note_created_at  timestamptz not null,
  content_sha256   text        not null,
  record_sha256    text        not null,
  sealed_at        timestamptz not null default now()
);

create table if not exists public.restore_audit (
  id             bigint      generated always as identity primary key,
  at             timestamptz not null default now(),
  note_id        uuid        not null,
  actor_id       uuid        not null,
  action         text        not null,
  before_sha256  text,
  after_sha256   text
);

create or replace function public.vault_content_sha256(p_text text) returns text
language sql immutable set search_path = public as $$
  select encode(sha256(convert_to(p_text, 'UTF8')), 'hex')
$$;

create or replace function public.vault_record_sha256(p_id uuid, p_owner uuid, p_title text, p_content text) returns text
language sql immutable set search_path = public as $$
  select encode(sha256(convert_to(
    jsonb_build_object('id', p_id, 'owner_id', p_owner, 'title', p_title, 'content', p_content)::text, 'UTF8')), 'hex')
$$;

create or replace function public.vault_seal_note() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.owner_id is not null then
    insert into public.note_backups (note_id, owner_id, title, content, note_created_at, content_sha256, record_sha256)
    values (new.id, new.owner_id, new.title, new.content, new.created_at,
            public.vault_content_sha256(new.content),
            public.vault_record_sha256(new.id, new.owner_id, new.title, new.content))
    on conflict (note_id) do nothing;
  end if;
  return new;
end $$;

create or replace function public.vault_backup_append_only() returns trigger
language plpgsql set search_path = public as $$
begin
  raise exception 'note_backups_are_append_only';
end $$;

drop trigger if exists vault_seal_note_after_insert on public.notes;
create trigger vault_seal_note_after_insert after insert on public.notes
  for each row execute function public.vault_seal_note();

drop trigger if exists vault_backup_no_change on public.note_backups;
create trigger vault_backup_no_change before update or delete on public.note_backups
  for each row execute function public.vault_backup_append_only();

drop trigger if exists vault_audit_no_change on public.restore_audit;
create trigger vault_audit_no_change before update or delete on public.restore_audit
  for each row execute function public.vault_backup_append_only();

create or replace function public.vault_restore_note(p_note_id uuid, p_user_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare
  b public.note_backups%rowtype;
  cur public.notes%rowtype;
  v_action text;
  v_before text;
begin
  select * into b from public.note_backups where note_id = p_note_id for update;
  if not found then
    return jsonb_build_object('status', 'no_backup');
  end if;

  if b.owner_id is distinct from p_user_id then
    insert into public.restore_audit (note_id, actor_id, action) values (p_note_id, p_user_id, 'refused_owner');
    return jsonb_build_object('status', 'forbidden');
  end if;

  -- 복구 직전에 사본을 다시 읽어 저장된 해시와 대조한다. 어긋나면 아무것도 바꾸지 않는다.
  if b.content_sha256 is distinct from public.vault_content_sha256(b.content)
     or b.record_sha256 is distinct from public.vault_record_sha256(b.note_id, b.owner_id, b.title, b.content) then
    insert into public.restore_audit (note_id, actor_id, action) values (p_note_id, p_user_id, 'refused_unverified');
    return jsonb_build_object('status', 'backup_unverified');
  end if;

  select * into cur from public.notes where id = p_note_id for update;
  if found then
    if cur.owner_id is distinct from b.owner_id then
      insert into public.restore_audit (note_id, actor_id, action) values (p_note_id, p_user_id, 'refused_owner_conflict');
      return jsonb_build_object('status', 'owner_conflict');
    end if;
    v_before := public.vault_content_sha256(cur.content);
    if cur.title = b.title and cur.content = b.content then
      v_action := 'unchanged';
    else
      update public.notes set title = b.title, content = b.content where id = p_note_id;
      v_action := 'updated';
    end if;
  else
    insert into public.notes (id, owner_id, title, content, created_at)
    values (b.note_id, b.owner_id, b.title, b.content, b.note_created_at);
    v_action := 'inserted';
  end if;

  insert into public.restore_audit (note_id, actor_id, action, before_sha256, after_sha256)
  values (p_note_id, p_user_id, v_action, v_before, b.content_sha256);

  return jsonb_build_object('status', 'restored', 'action', v_action, 'id', b.note_id,
                            'ownerId', b.owner_id, 'contentSha256', b.content_sha256);
end $$;

alter table public.note_backups enable row level security;
alter table public.restore_audit enable row level security;

revoke all on public.note_backups from public, anon, authenticated, service_role;
revoke all on public.restore_audit from public, anon, authenticated, service_role;
grant select on public.note_backups to service_role;
grant select on public.restore_audit to service_role;

revoke all on function public.vault_content_sha256(text) from public, anon, authenticated;
revoke all on function public.vault_record_sha256(uuid, uuid, text, text) from public, anon, authenticated;
revoke all on function public.vault_seal_note() from public, anon, authenticated;
revoke all on function public.vault_backup_append_only() from public, anon, authenticated;
revoke all on function public.vault_restore_note(uuid, uuid) from public, anon, authenticated;
grant execute on function public.vault_content_sha256(text) to service_role;
grant execute on function public.vault_record_sha256(uuid, uuid, text, text) to service_role;
grant execute on function public.vault_restore_note(uuid, uuid) to service_role;

-- 이미 있는 메모(소유자가 있는 것)를 지금 모습 그대로 사본으로 봉인한다.
insert into public.note_backups (note_id, owner_id, title, content, note_created_at, content_sha256, record_sha256)
select id, owner_id, title, content, created_at,
       public.vault_content_sha256(content),
       public.vault_record_sha256(id, owner_id, title, content)
from public.notes
where owner_id is not null
on conflict (note_id) do nothing;
