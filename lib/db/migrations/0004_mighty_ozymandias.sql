ALTER TABLE "users" ADD COLUMN "marketing_opted_out" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "alert_emails_opted_out" boolean DEFAULT false NOT NULL;