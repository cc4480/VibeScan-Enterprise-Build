CREATE TABLE "deleted_account_trials" (
	"email_hash" text PRIMARY KEY NOT NULL,
	"period_start" timestamp with time zone NOT NULL,
	"scans_used" integer NOT NULL
);
