CREATE TABLE "billing_subscriptions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"plan" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"url_limit" integer NOT NULL,
	"current_period_end" timestamp with time zone,
	"grandfathered" boolean DEFAULT false NOT NULL,
	"stripe_customer_id" text,
	"stripe_subscription_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "billing_subscriptions_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
CREATE INDEX "idx_billing_sub_user_id" ON "billing_subscriptions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "idx_billing_sub_status" ON "billing_subscriptions" USING btree ("status");--> statement-breakpoint
CREATE UNIQUE INDEX "uq_billing_sub_stripe_sub" ON "billing_subscriptions" USING btree ("stripe_subscription_id");