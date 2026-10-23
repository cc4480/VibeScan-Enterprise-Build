CREATE TABLE "stripe_events" (
	"id" text PRIMARY KEY NOT NULL,
	"type" text NOT NULL,
	"processed_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "billing_subscriptions" ADD COLUMN "included_scans_remaining" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN "paid_with" text;