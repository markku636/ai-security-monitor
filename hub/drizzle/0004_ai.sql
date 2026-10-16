CREATE TABLE "ai_analyses" (
	"id" text PRIMARY KEY NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"finished_at" timestamp with time zone,
	"provider" text NOT NULL,
	"scope" text NOT NULL,
	"agent_id" text,
	"prompt" text NOT NULL,
	"status" text DEFAULT 'running' NOT NULL,
	"result_text" text,
	"tools_called" integer DEFAULT 0 NOT NULL,
	"events" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"error" text,
	"created_by" text NOT NULL
);
--> statement-breakpoint
CREATE INDEX "ai_analyses_created_idx" ON "ai_analyses" USING btree ("created_at");