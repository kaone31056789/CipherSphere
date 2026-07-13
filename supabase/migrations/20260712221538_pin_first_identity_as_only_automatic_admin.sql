create or replace function public.ciphersphere_handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
declare
  desired_username text;
  assigned_role text;
begin
  perform pg_advisory_xact_lock(20260713);

  desired_username := lower(regexp_replace(
    coalesce(nullif(new.raw_user_meta_data ->> 'username', ''), split_part(new.email, '@', 1), 'user'),
    '[^a-zA-Z0-9_.-]+', '_', 'g'
  ));
  desired_username := left(trim(both '_' from desired_username), 70);
  if desired_username = '' then desired_username := 'user'; end if;
  if exists (select 1 from public.app_user where lower(username) = lower(desired_username)) then
    desired_username := desired_username || '_' || substr(new.id::text, 1, 8);
  end if;

  assigned_role := case
    when exists (select 1 from public.app_user) then 'user'
    else 'admin'
  end;

  insert into public.app_user (auth_subject, username, full_name, email, role, is_active)
  values (
    new.id,
    desired_username,
    left(coalesce(nullif(new.raw_user_meta_data ->> 'full_name', ''), desired_username), 120),
    lower(new.email),
    assigned_role,
    true
  )
  on conflict (auth_subject) do update set
    email = excluded.email,
    full_name = excluded.full_name;
  return new;
end;
$function$;

revoke all on function public.ciphersphere_handle_new_auth_user() from public, anon, authenticated;
grant execute on function public.ciphersphere_handle_new_auth_user() to service_role;
