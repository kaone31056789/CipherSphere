alter table public.app_user
  add column if not exists avatar_filename varchar(255);

alter table public.app_user
  drop constraint if exists app_user_avatar_filename_length;

alter table public.app_user
  add constraint app_user_avatar_filename_length
  check (
    avatar_filename is null
    or char_length(avatar_filename) between 1 and 255
  );
