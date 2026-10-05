-- Share tokens are stored as a SHA-256 hash, not in the clear (audit finding #19). Existing links keep
-- working: each row's hash is computed from its current token before the token is dropped. sha256() is
-- built in from PostgreSQL 11, so no extension is needed. The application hashes the token's UTF-8 bytes
-- and hex-encodes the digest, which is what this expression produces.
ALTER TABLE "report_shares" ADD COLUMN "token_hash" text;--> statement-breakpoint
UPDATE "report_shares" SET "token_hash" = encode(sha256(convert_to("token", 'UTF8')), 'hex');--> statement-breakpoint
ALTER TABLE "report_shares" ALTER COLUMN "token_hash" SET NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "uq_report_shares_token_hash" ON "report_shares" USING btree ("token_hash");--> statement-breakpoint
DROP INDEX "uq_report_shares_token";--> statement-breakpoint
ALTER TABLE "report_shares" DROP COLUMN "token";
