CREATE TABLE "auth_tokens" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar NOT NULL,
	"token_hash" varchar NOT NULL,
	"purpose" varchar NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "auth_tokens_token_hash_unique" UNIQUE("token_hash")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"sid" varchar PRIMARY KEY NOT NULL,
	"sess" jsonb NOT NULL,
	"expire" timestamp NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" varchar,
	"first_name" varchar,
	"last_name" varchar,
	"profile_image_url" varchar,
	"deepseek_api_key_encrypted" varchar,
	"deepseek_api_key_last4" varchar(4),
	"password_hash" varchar,
	"email_verified_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
CREATE TABLE "cert_expiry_alerts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subscription_id" uuid NOT NULL,
	"expiry_date" timestamp with time zone NOT NULL,
	"days_remaining" integer NOT NULL,
	"alert_threshold" integer NOT NULL,
	"sent_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "credits" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"balance" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "credits_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
CREATE TABLE "cve_alerts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subscription_id" uuid NOT NULL,
	"cve_id" text NOT NULL,
	"cve_summary" text NOT NULL,
	"affected_tech" text NOT NULL,
	"severity" text NOT NULL,
	"epss_score" real,
	"epss_percentile" real,
	"trigger_scan_id" uuid,
	"detected_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dismissed_findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"target_url" text NOT NULL,
	"finding_fingerprint" text NOT NULL,
	"finding_name" text NOT NULL,
	"finding_category" text NOT NULL,
	"reason" text DEFAULT 'false_positive',
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "eol_cache" (
	"key" text PRIMARY KEY NOT NULL,
	"payload" jsonb NOT NULL,
	"fetched_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "monitor_regressions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subscription_id" uuid NOT NULL,
	"scan_id" uuid,
	"check_id" text NOT NULL,
	"check_title" text NOT NULL,
	"severity" text NOT NULL,
	"detected_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "monitor_score_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"subscription_id" uuid NOT NULL,
	"scan_id" uuid,
	"grade" text NOT NULL,
	"risk_score" integer NOT NULL,
	"critical_count" integer DEFAULT 0 NOT NULL,
	"high_count" integer DEFAULT 0 NOT NULL,
	"scanned_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "monitor_subscriptions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"user_email" text NOT NULL,
	"target_url" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"subscribed_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"last_scan_at" timestamp with time zone,
	"last_report_id" uuid,
	"next_scan_at" timestamp with time zone,
	"webhook_url" text,
	"stripe_subscription_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "oob_interactions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"token" varchar NOT NULL,
	"method" varchar,
	"path" text,
	"source_ip" varchar,
	"user_agent" text,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "oob_tokens" (
	"token" varchar PRIMARY KEY NOT NULL,
	"scan_id" uuid,
	"context" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "report_shares" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"report_id" uuid NOT NULL,
	"user_id" text NOT NULL,
	"token" text NOT NULL,
	"expires_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" uuid,
	"user_id" text NOT NULL,
	"target_url" text NOT NULL,
	"tier" text NOT NULL,
	"scanned_at" timestamp with time zone DEFAULT now() NOT NULL,
	"duration" integer,
	"data" jsonb NOT NULL,
	"pdf_url" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scans" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"user_email" text NOT NULL,
	"target_url" text NOT NULL,
	"tier" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"stripe_session_id" text,
	"stripe_payment_intent_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"started_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"error" text,
	"credentials_encrypted" text,
	"secondary_credentials_encrypted" text,
	"credentials_authorized_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "cert_expiry_alerts" ADD CONSTRAINT "cert_expiry_alerts_subscription_id_monitor_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."monitor_subscriptions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cve_alerts" ADD CONSTRAINT "cve_alerts_subscription_id_monitor_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."monitor_subscriptions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "monitor_regressions" ADD CONSTRAINT "monitor_regressions_subscription_id_monitor_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."monitor_subscriptions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "monitor_regressions" ADD CONSTRAINT "monitor_regressions_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "monitor_score_history" ADD CONSTRAINT "monitor_score_history_subscription_id_monitor_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "public"."monitor_subscriptions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "monitor_score_history" ADD CONSTRAINT "monitor_score_history_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oob_tokens" ADD CONSTRAINT "oob_tokens_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "report_shares" ADD CONSTRAINT "report_shares_report_id_reports_id_fk" FOREIGN KEY ("report_id") REFERENCES "public"."reports"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "IDX_auth_tokens_user" ON "auth_tokens" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "IDX_session_expire" ON "sessions" USING btree ("expire");--> statement-breakpoint
CREATE INDEX "idx_cert_expiry_sub_id" ON "cert_expiry_alerts" USING btree ("subscription_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_cert_expiry_sub_threshold" ON "cert_expiry_alerts" USING btree ("subscription_id","alert_threshold","expiry_date");--> statement-breakpoint
CREATE INDEX "idx_cve_alerts_subscription_id" ON "cve_alerts" USING btree ("subscription_id");--> statement-breakpoint
CREATE INDEX "idx_cve_alerts_cve_id" ON "cve_alerts" USING btree ("cve_id");--> statement-breakpoint
CREATE INDEX "idx_dismissed_user_target" ON "dismissed_findings" USING btree ("user_id","target_url");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_dismissed_user_target_fp" ON "dismissed_findings" USING btree ("user_id","target_url","finding_fingerprint");--> statement-breakpoint
CREATE INDEX "idx_regressions_sub_id" ON "monitor_regressions" USING btree ("subscription_id");--> statement-breakpoint
CREATE INDEX "idx_regressions_scan_id" ON "monitor_regressions" USING btree ("scan_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_regression_sub_scan_check" ON "monitor_regressions" USING btree ("subscription_id","scan_id","check_id");--> statement-breakpoint
CREATE INDEX "idx_score_history_sub_id" ON "monitor_score_history" USING btree ("subscription_id");--> statement-breakpoint
CREATE INDEX "idx_score_history_scanned_at" ON "monitor_score_history" USING btree ("scanned_at");--> statement-breakpoint
CREATE INDEX "idx_monitor_user_id" ON "monitor_subscriptions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_monitor_status" ON "monitor_subscriptions" USING btree ("status");--> statement-breakpoint
CREATE INDEX "idx_monitor_target" ON "monitor_subscriptions" USING btree ("target_url");--> statement-breakpoint
CREATE INDEX "idx_monitor_next_scan" ON "monitor_subscriptions" USING btree ("next_scan_at");--> statement-breakpoint
CREATE INDEX "idx_oob_interactions_token" ON "oob_interactions" USING btree ("token");--> statement-breakpoint
CREATE INDEX "idx_oob_tokens_scan" ON "oob_tokens" USING btree ("scan_id");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_report_shares_token" ON "report_shares" USING btree ("token");--> statement-breakpoint
CREATE INDEX "idx_report_shares_report_id" ON "report_shares" USING btree ("report_id");--> statement-breakpoint
CREATE INDEX "idx_report_shares_user_id" ON "report_shares" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_reports_user_id" ON "reports" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_reports_scan_id" ON "reports" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "idx_scans_user_id" ON "scans" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_scans_status" ON "scans" USING btree ("status");