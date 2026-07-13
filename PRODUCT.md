# CipherSphere product contract

Register: product

CipherSphere is a focused secure workspace for encrypting, decrypting, storing, and sharing sensitive files or text. Supabase Auth owns identity and recovery, while the Flask server owns the application data model and authorization decisions.

## Core journeys

- Account access: register with Supabase, confirm email when required, sign in with Google or a password, recover access by email, and sign out.
- Protect data: choose an algorithm, provide text or a file, optionally supply a key, and save the encrypted result to the vault.
- Recover data: provide encrypted text or a file and the matching key, then copy or download the result.
- Manage data: review vault contents, download, share, or delete an item.
- Collaborate: review received and sent shares with clear owner, permission, and expiry information. Exchange encryption keys outside CipherSphere.
- Maintain an account: update the display name or change the Supabase password.
- Administer the service: review system status, users, files, activity, and settings; create users and manage scoped records.

## Identity and administrator rules

- Every Supabase Auth identity is mirrored to one `app_user` profile through its Auth UUID.
- The first Supabase identity created—including through Google—becomes the initial administrator; later identities are members.
- No default administrator credentials exist in source control.
- Administrator capability is visible only to authenticated administrators and is labeled as privileged access.
- The final active administrator cannot be disabled, deleted, or demoted from the admin interface.
- Passwords, Google OAuth, email confirmation, and recovery tokens remain under Supabase Auth. The application does not implement local password hashes, security questions, or profile-picture identity checks.

## Data and cryptography rules

- Production records use the Supabase PostgreSQL schema in `supabase/migrations/` and a Session Pooler `DATABASE_URL`.
- Serverless production stores encrypted objects, temporary downloads, and avatars in the private `ciphersphere-private` Supabase Storage bucket; local disk is development-only.
- Application tables are server-owned. Row-level security is enabled and the public Data API roles are denied direct table access.
- CSPH v1 is the only current ciphertext envelope. Its version and algorithm identifier are validated before decryption.
- AES and hybrid RSA payloads use AES-256-GCM; Fernet is authenticated. File metadata is included inside the authenticated payload.
- Never imply that a lost encryption key can be recovered. Results tell users to store keys separately.
- Sharing records never contain encryption keys. Users must exchange keys through a separate secure channel.
- Wrong keys, modified data, unsupported algorithms, and malformed envelopes fail without returning partial plaintext.

## Interface rules

- Destructive actions are explicit, contextual, and never presented as primary actions.
- Empty, success, and error states explain the next useful action.
- Optional template context degrades to an honest empty or unavailable state.
- Security status is communicated in words, not color alone.
- Cipher Noir and Signal Atelier are complete interface systems rather than light/dark recolors; they preserve the same semantic structure and workflows.
- The theme selector is available in the top-right navigation and Profile settings, persists locally, and transitions without losing focus or navigation state.
- Persistent effects have a visible pause/resume control and respect reduced-motion preferences.
- Profile images are optional, privately served to the authenticated owner, and never used as an authentication factor.
- Production starts only with a stable secret, HTTPS callbacks, secure cookies, migrated PostgreSQL, and persistent private storage.

## Supported journeys and endpoints

Primary endpoints are `login`, `register`, `logout`, `forgot_password`, `reset_password`, `dashboard`, `encrypt`, `decrypt`, `vault`, `shared_files`, `profile`, `admin_dashboard`, `admin_users`, `admin_create_user`, `admin_files`, `admin_activity`, and `admin_settings`. Supporting download, share, delete, profile, and admin mutation endpoints remain contextual actions.

## Acceptance baseline

Every page has a descriptive title, one `h1`, one `main`, logical headings, keyboard access, visible focus, labeled form controls, associated errors, useful autocomplete values, responsive layouts, accessible tables, and both complete interface systems. Account flows use Supabase end to end, the first identity is designated as administrator, CSPH v1 round trips preserve authenticated content and metadata, and production records persist through the Supabase Session Pooler connection.
