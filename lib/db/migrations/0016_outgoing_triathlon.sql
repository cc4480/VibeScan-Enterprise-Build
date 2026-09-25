CREATE TABLE "pending_registrations" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar NOT NULL,
	"password_hash" varchar NOT NULL,
	"signup_network" varchar,
	"anon_user_id" varchar,
	"challenge_hash" varchar NOT NULL,
	"code_hash" varchar NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "pending_registrations_challenge_hash_unique" UNIQUE("challenge_hash")
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "signup_network" varchar;--> statement-breakpoint
CREATE INDEX "IDX_pending_registrations_email" ON "pending_registrations" USING btree ("email");--> statement-breakpoint
CREATE INDEX "IDX_users_signup_network" ON "users" USING btree ("signup_network","created_at");