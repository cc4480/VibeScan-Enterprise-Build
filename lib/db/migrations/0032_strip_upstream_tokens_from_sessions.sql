-- Audit finding: the upstream OIDC access_token and refresh_token (and the expiry that went with
-- them) were stored in sessions.sess, in plaintext jsonb. Nothing reads them back, so they are
-- removed from every existing session. sess is jsonb, so the `?|` test and the `-` operator work on
-- the top-level keys; the user object is untouched. The application no longer writes these keys
-- (see SessionData and persistedSession in lib/auth.ts).
UPDATE "sessions"
   SET "sess" = "sess" - 'access_token' - 'refresh_token' - 'expires_at'
 WHERE "sess" ?| ARRAY['access_token', 'refresh_token', 'expires_at'];
