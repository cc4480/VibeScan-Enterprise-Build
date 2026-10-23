CREATE TABLE "team_members" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"member_id" text,
	"invited_email" text NOT NULL,
	"token_hash" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"accepted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE UNIQUE INDEX "idx_team_members_owner_email" ON "team_members" USING btree ("user_id","invited_email");--> statement-breakpoint
CREATE UNIQUE INDEX "idx_team_members_token" ON "team_members" USING btree ("token_hash");--> statement-breakpoint
CREATE INDEX "idx_team_members_member" ON "team_members" USING btree ("member_id");