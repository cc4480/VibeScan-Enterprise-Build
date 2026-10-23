CREATE TABLE "feedback" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text,
	"email" text,
	"message" text NOT NULL,
	"rating" integer,
	"context" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
