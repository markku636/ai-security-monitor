ALTER TABLE "agents" ADD COLUMN "intel_checked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "intel_feeds" jsonb;