CREATE TABLE "email_suppressions" (
	"email" varchar PRIMARY KEY NOT NULL,
	"scope" varchar NOT NULL,
	"reason" varchar NOT NULL,
	"detail" varchar,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX "IDX_email_suppressions_scope" ON "email_suppressions" USING btree ("scope");