-- Audit finding #17: deleteSessionsForUser() filters on sess->'user'->>'id', which lives inside the JSON
-- column, so with no index every password reset or account deletion scanned the whole sessions table.
-- This expression index serves that lookup. The application query must repeat the expression exactly
-- (see sessionUserIdExpr in lib/db/src/schema/auth.ts) or Postgres will not consider the index.
-- Plain CREATE INDEX, not CONCURRENTLY: CONCURRENTLY cannot run inside a transaction, and drizzle runs
-- the whole migration in one. sessions is small and short-lived (rows expire after 7 days and are purged
-- daily), so the brief write lock while the index builds is acceptable.
CREATE INDEX "IDX_session_user_id" ON "sessions" USING btree (("sess"->'user'->>'id'));
