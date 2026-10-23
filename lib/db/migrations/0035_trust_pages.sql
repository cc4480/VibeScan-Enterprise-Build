CREATE TABLE "trust_pages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"domain" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"display_name" text,
	"accent" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_trust_pages_domain" ON "trust_pages" USING btree ("domain");--> statement-breakpoint
CREATE INDEX "idx_trust_pages_user" ON "trust_pages" USING btree ("user_id");