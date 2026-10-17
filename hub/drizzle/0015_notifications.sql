CREATE TABLE "notification_channels" (
	"id" text PRIMARY KEY NOT NULL,
	"kind" text NOT NULL,
	"name" text NOT NULL,
	"config" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text,
	"last_ok_at" timestamp with time zone,
	"last_error" text,
	"last_error_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "notification_log" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"rule_id" text,
	"channel_id" text NOT NULL,
	"event" text NOT NULL,
	"title" text NOT NULL,
	"body" text NOT NULL,
	"link" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"error" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"sent_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "notification_rules" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"event" text NOT NULL,
	"min_severity" text,
	"agent_id" text,
	"channel_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text
);
--> statement-breakpoint
CREATE TABLE "notification_seen" (
	"rule_id" text NOT NULL,
	"key" text NOT NULL,
	"at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "notification_seen_rule_id_key_pk" PRIMARY KEY("rule_id","key")
);
--> statement-breakpoint
CREATE INDEX "notification_log_status_idx" ON "notification_log" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "notification_seen_at_idx" ON "notification_seen" USING btree ("at");