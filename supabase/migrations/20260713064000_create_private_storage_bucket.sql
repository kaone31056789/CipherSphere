insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'ciphersphere-private',
  'ciphersphere-private',
  false,
  52428800,
  array['application/octet-stream', 'image/webp']
)
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

-- No anon/authenticated object policies are created. With Storage RLS enabled,
-- only the server-side secret key may access this private bucket.
