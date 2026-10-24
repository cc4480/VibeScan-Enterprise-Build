CREATE TABLE "ticket_destinations" (
	"user_id" text NOT NULL,
	"provider" text NOT NULL,
	"target" text NOT NULL,
	"site" text,
	"account_email" text,
	"issue_type" text,
	"external_id" text,
	"credential_encrypted" text NOT NULL,
	"auto_file" boolean DEFAULT false NOT NULL,
	"auto_min_severity" text DEFAULT 'high' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_destinations_user_id_provider_pk" PRIMARY KEY("user_id","provider")
);
--> statement-breakpoint
CREATE TABLE "tickets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"provider" text NOT NULL,
	"destination" text NOT NULL,
	"finding_key" text NOT NULL,
	"report_id" uuid,
	"ticket_key" text NOT NULL,
	"ticket_url" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_tickets_user_provider_dest_finding" ON "tickets" USING btree ("user_id","provider","destination","finding_key");--> statement-breakpoint
CREATE INDEX "idx_tickets_report" ON "tickets" USING btree ("report_id");