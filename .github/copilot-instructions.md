# CipherSphere project instructions

CipherSphere is a Flask application with Supabase Auth, a Supabase PostgreSQL production schema, SQLAlchemy records, CSPH v1 authenticated encryption, and an accessible skeuomorphic interface.

## Architecture boundaries

- Use the `create_app` factory in `ciphersphere/__init__.py`; keep `app.py` and `wsgi.py` as thin entry points.
- Keep authentication in `ciphersphere/auth_service.py`. Supabase owns passwords, Google OAuth, email confirmation, sign-in, and recovery.
- Link an application profile to `auth.users.id` through `app_user.auth_subject`. Do not add local password hashes, security questions, reset-token storage, or profile-picture authentication.
- Make production schema changes through ordered files in `supabase/migrations/` and keep the SQLAlchemy models aligned with them.
- Treat application tables as server-owned. Preserve RLS, explicit server-only policies, and least-privilege grants.
- Use the Supabase Session Pooler URI in `DATABASE_URL` for deployment. SQLite is an isolated development fallback only.

## Administrator behavior

- The database trigger designates the first Supabase identity created as the initial administrator.
- Keep Google OAuth on the server-side PKCE flow; never expose Supabase access or refresh tokens to browser JavaScript.
- Do not add hard-coded administrator credentials.
- Preserve server-side role checks and protection for the final active administrator.
- Use the optional server-only Supabase secret key only for administrative Auth operations; never expose it in templates or JavaScript.

## Cryptography

- Preserve the CSPH v1 binary envelope and explicit version/algorithm validation.
- Use authenticated primitives from `cryptography`: AES-256-GCM, Fernet, and RSA-OAEP-SHA256 wrapping a random AES-256-GCM content key.
- Keep file metadata inside the authenticated payload.
- Never store encryption keys in sharing or vault database records, log them, or imply that the service can recover them.
- Fail closed on the wrong key, modified ciphertext, an unsupported algorithm, or a malformed envelope.

## Interface

- Follow `DESIGN.md`: restrained graphite-and-silver skeuomorphism with emerald focus and action accents.
- Do not introduce cyberpunk neon, glass blur, particles, animated decoration, gradient text, remote fonts, or exaggerated security claims.
- Prefer semantic HTML and native controls. Maintain the skip link, landmarks, one page `h1`, explicit labels, useful autocomplete values, connected hints/errors, visible keyboard focus, text status, accessible tables, responsive behavior, and reduced-motion support.
- Keep JavaScript progressive. Core navigation and form submission must remain usable without it.
- Treat 44px targets, sufficient contrast, keyboard operation, and clear error recovery as release requirements.

## Repository hygiene

- Keep runtime data under ignored `instance/` directories.
- Do not commit `.env`, credentials, Supabase secret/service-role keys, database passwords, plaintext input, generated ciphertext, decrypted output, screenshots, debug scripts, temporary utilities, or test artifacts.
- Update README, PRODUCT, DESIGN, `.env.example`, migrations, and models together when their contracts change.
