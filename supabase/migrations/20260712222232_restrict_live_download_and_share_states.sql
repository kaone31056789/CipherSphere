alter table public.shared_file
  alter column permissions set default 'download',
  drop constraint if exists shared_file_permissions_check,
  add constraint shared_file_permissions_check check (permissions = 'download');

alter table public.download_token
  drop constraint if exists download_token_storage_area_check,
  add constraint download_token_storage_area_check check (storage_area in ('vault', 'temp'));
