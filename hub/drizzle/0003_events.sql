CREATE TABLE "agent_summaries" (
	"agent_id" text NOT NULL,
	"kind" text NOT NULL,
	"at" timestamp with time zone NOT NULL,
	"summary" jsonb NOT NULL,
	CONSTRAINT "agent_summaries_agent_id_kind_pk" PRIMARY KEY("agent_id","kind")
);
--> statement-breakpoint
CREATE TABLE "crash_records" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"time" timestamp with time zone NOT NULL,
	"kind" text NOT NULL,
	"code" text,
	"name" text,
	"module" text,
	"process" text,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"dedupe_key" text NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "security_events" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"rule" text NOT NULL,
	"severity" text NOT NULL,
	"count" integer DEFAULT 1 NOT NULL,
	"first_at" timestamp with time zone NOT NULL,
	"last_at" timestamp with time zone NOT NULL,
	"source_ip" text,
	"user_name" text,
	"detail" text DEFAULT '' NOT NULL,
	"intel" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"dedupe_key" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "agent_summaries" ADD CONSTRAINT "agent_summaries_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "crash_records" ADD CONSTRAINT "crash_records_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "crash_records_dedupe" ON "crash_records" USING btree ("agent_id","dedupe_key");--> statement-breakpoint
CREATE INDEX "crash_records_time_idx" ON "crash_records" USING btree ("time");--> statement-breakpoint
CREATE INDEX "crash_records_agent_time_idx" ON "crash_records" USING btree ("agent_id","time");--> statement-breakpoint
CREATE INDEX "crash_records_kind_code_idx" ON "crash_records" USING btree ("kind","code");--> statement-breakpoint
CREATE UNIQUE INDEX "security_events_dedupe" ON "security_events" USING btree ("agent_id","dedupe_key");--> statement-breakpoint
CREATE INDEX "security_events_rule_last_idx" ON "security_events" USING btree ("rule","last_at");--> statement-breakpoint
CREATE INDEX "security_events_source_idx" ON "security_events" USING btree ("source_ip");