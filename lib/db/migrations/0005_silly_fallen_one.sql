CREATE TABLE "pending_logins" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"challenge_hash" varchar NOT NULL,
	"code_hash" varchar NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pending_logins_challenge_hash_unique" UNIQUE("challenge_hash")
);
--> statement-breakpoint
CREATE INDEX "IDX_pending_logins_user" ON "pending_logins" USING btree ("user_id");