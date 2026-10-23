CREATE TABLE "github_installations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"installation_id" text NOT NULL,
	"account_login" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_github_installations_user_installation" ON "github_installations" USING btree ("user_id","installation_id");--> statement-breakpoint
CREATE INDEX "idx_github_installations_user" ON "github_installations" USING btree ("user_id");