CREATE TABLE "ip_reputation" (
	"ip" text PRIMARY KEY NOT NULL,
	"results" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"queried_at" timestamp with time zone DEFAULT now() NOT NULL,
	"queried_by" text
);
--> statement-breakpoint
CREATE INDEX "ip_reputation_queried_idx" ON "ip_reputation" USING btree ("queried_at");