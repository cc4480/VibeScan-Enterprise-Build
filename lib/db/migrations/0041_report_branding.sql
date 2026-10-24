ALTER TABLE "users" ADD COLUMN "brand_name" varchar(60);--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "brand_powered_by" boolean DEFAULT true NOT NULL;