alter table public.app_user
  drop column if exists password_hash,
  drop column if exists security_question,
  drop column if exists security_answer_hash,
  drop column if exists profile_picture,
  drop column if exists reset_token_hash,
  drop column if exists reset_token_expires_at;
