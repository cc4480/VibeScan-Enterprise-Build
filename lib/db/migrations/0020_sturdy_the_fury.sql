CREATE TABLE "finding_verifications" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"report_id" uuid NOT NULL,
	"finding_id" text NOT NULL,
	"scan_id" uuid NOT NULL,
	"verdict" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"completed_at" timestamp with time zone
);
--> statement-breakpoint
CREATE INDEX "idx_verifications_report" ON "finding_verifications" USING btree ("report_id");--> statement-breakpoint
CREATE INDEX "idx_verifications_scan" ON "finding_verifications" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "idx_verifications_user_created" ON "finding_verifications" USING btree ("user_id","created_at");