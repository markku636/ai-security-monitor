CREATE TABLE "actions" (
	"id" text PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"finding_id" text,
	"kind" text NOT NULL,
	"params" jsonb NOT NULL,
	"params_hash" text NOT NULL,
	"reason" text DEFAULT '' NOT NULL,
	"destructive" boolean DEFAULT false NOT NULL,
	"requires_elevation" boolean DEFAULT true NOT NULL,
	"proposed_by" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"reviewed_by" text,
	"reviewed_at" timestamp with time zone,
	"review_note" text,
	"expires_at" timestamp with time zone NOT NULL,
	"dispatched_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"result_ok" boolean,
	"result_output" text
);
--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "token_hash" text;--> statement-breakpoint
ALTER TABLE "actions" ADD CONSTRAINT "actions_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "actions_agent_status_idx" ON "actions" USING btree ("agent_id","status");--> statement-breakpoint
CREATE INDEX "actions_status_created_idx" ON "actions" USING btree ("status","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "actions_open_unique" ON "actions" USING btree ("agent_id","kind","params_hash") WHERE status in ('pending', 'approved', 'dispatched');