CREATE TABLE "domain_verifications" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"domain" text NOT NULL,
	"token" text NOT NULL,
	"method" text,
	"verified_at" timestamp with time zone,
	"last_checked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_domain_verif_user_domain" ON "domain_verifications" USING btree ("user_id","domain");--> statement-breakpoint
CREATE INDEX "idx_domain_verif_user" ON "domain_verifications" USING btree ("user_id");