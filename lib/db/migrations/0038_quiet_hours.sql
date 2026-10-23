ALTER TABLE "users" ADD COLUMN "quiet_hours_start" integer;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "quiet_hours_end" integer;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "quiet_hours_timezone" text;