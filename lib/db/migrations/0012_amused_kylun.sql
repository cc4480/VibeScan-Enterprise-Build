CREATE TABLE "monitor_pulse_checks" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subscription_id" uuid NOT NULL,
	"checked_at" timestamp with time zone DEFAULT now() NOT NULL,
	"reachable" boolean NOT NULL,
	"http_status" integer,
	"response_time_ms" integer,
	"final_url" text,
	"header_fingerprint" text,
	"present_headers" jsonb,
	"hsts_bucket" text,
	"cert_expires_at" timestamp with time zone,
	"cert_days_remaining" integer,
	"failure_reason" text
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "notify_availability_opted_out" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "notify_drift_opted_out" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "monitor_pulse_checks" ADD CONSTRAINT "monitor_pulse_checks_subscription_id_monitor_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."monitor_subscriptions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "idx_pulse_sub_checked" ON "monitor_pulse_checks" USING btree ("subscription_id","checked_at");--> statement-breakpoint
CREATE INDEX "idx_pulse_checked_at" ON "monitor_pulse_checks" USING btree ("checked_at");