CREATE TABLE "agent_group_members" (
	"group_id" text NOT NULL,
	"agent_id" text NOT NULL,
	CONSTRAINT "agent_group_members_group_id_agent_id_pk" PRIMARY KEY("group_id","agent_id")
);
--> statement-breakpoint
CREATE TABLE "agent_groups" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"description" text DEFAULT '' NOT NULL,
	"config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text
);
--> statement-breakpoint
CREATE TABLE "response_blocks" (
	"id" text PRIMARY KEY NOT NULL,
	"rule_id" text,
	"agent_id" text NOT NULL,
	"ip" text NOT NULL,
	"reason" text DEFAULT '' NOT NULL,
	"level" integer DEFAULT 0 NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"blocked_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"released_at" timestamp with time zone,
	"block_action_id" text,
	"unblock_action_id" text
);
--> statement-breakpoint
CREATE TABLE "response_rules" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"trigger" text NOT NULL,
	"params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"block_minutes" integer DEFAULT 60 NOT NULL,
	"escalate" boolean DEFAULT true NOT NULL,
	"group_id" text,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text
);
--> statement-breakpoint
ALTER TABLE "agent_group_members" ADD CONSTRAINT "agent_group_members_group_id_agent_groups_id_fk" FOREIGN KEY ("group_id") REFERENCES "public"."agent_groups"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "agent_group_members" ADD CONSTRAINT "agent_group_members_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "response_blocks" ADD CONSTRAINT "response_blocks_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agent_group_members_agent_idx" ON "agent_group_members" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX "response_blocks_status_idx" ON "response_blocks" USING btree ("status","expires_at");--> statement-breakpoint
CREATE INDEX "response_blocks_agent_ip_idx" ON "response_blocks" USING btree ("agent_id","ip");