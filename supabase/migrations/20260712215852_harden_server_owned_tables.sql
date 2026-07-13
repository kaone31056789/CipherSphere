create policy app_user_server_only on public.app_user
for all to anon, authenticated using (false) with check (false);
create policy encrypted_file_server_only on public.encrypted_file
for all to anon, authenticated using (false) with check (false);
create policy activity_log_server_only on public.activity_log
for all to anon, authenticated using (false) with check (false);
create policy shared_file_server_only on public.shared_file
for all to anon, authenticated using (false) with check (false);
create policy download_token_server_only on public.download_token
for all to anon, authenticated using (false) with check (false);
create policy system_settings_server_only on public.system_settings
for all to anon, authenticated using (false) with check (false);

create index system_settings_updated_by_idx on public.system_settings (updated_by);
