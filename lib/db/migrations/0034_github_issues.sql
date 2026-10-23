CREATE TABLE "github_issue_destinations" (
	"user_id" text PRIMARY KEY NOT NULL,
	"repo_full_name" text NOT NULL,
	"token_encrypted" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "github_issues" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"repo_full_name" text NOT NULL,
	"finding_key" text NOT NULL,
	"report_id" uuid,
	"issue_number" integer NOT NULL,
	"issue_url" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_github_issues_user_repo_finding" ON "github_issues" USING btree ("user_id","repo_full_name","finding_key");--> statement-breakpoint
CREATE INDEX "idx_github_issues_report" ON "github_issues" USING btree ("report_id");