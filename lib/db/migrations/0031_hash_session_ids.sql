-- Audit finding: session ids were stored in plaintext, so anyone who could read the sessions table
-- (a backup, a SQL console, a replica) could paste a value into a Cookie header and be signed in.
-- From now on sessions.sid holds sha256(raw id) as lowercase hex, and the cookie keeps the raw id
-- (hashSessionId in lib/auth.ts). This statement converts the rows that already exist, so nobody is
-- logged out. It is correct only because drizzle runs each migration exactly once, and so it does NOT
-- check whether a value is already hashed: raw ids are 64 hex characters too, so a length test cannot
-- tell them apart. Do not re-run it by hand against a table that is already hashed.
-- Same digest as Node's createHash('sha256').update(sid).digest('hex') over the UTF-8 bytes.
UPDATE "sessions" SET "sid" = encode(sha256(convert_to("sid", 'UTF8')), 'hex');
