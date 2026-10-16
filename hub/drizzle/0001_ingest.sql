CREATE TABLE "agents" (
	"id" text PRIMARY KEY NOT NULL,
	"hostname" text NOT NULL,
	"os_family" text DEFAULT '' NOT NULL,
	"os_name" text,
	"os_version" text,
	"arch" text DEFAULT '' NOT NULL,
	"version" text DEFAULT '' NOT NULL,
	"ips" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"labels" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"notes" text,
	"elevated" boolean DEFAULT false NOT NULL,
	"partial" boolean DEFAULT false NOT NULL,
	"accept_remote_actions" boolean DEFAULT false NOT NULL,
	"service_mode" boolean DEFAULT false NOT NULL,
	"key_index" integer,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_heartbeat_at" timestamp with time zone,
	"last_report_at" timestamp with time zone,
	"last_report_id" text,
	"last_snapshot_at" timestamp with time zone,
	"score" jsonb,
	"sev_counts" jsonb DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::jsonb NOT NULL,
	"open_findings" integer DEFAULT 0 NOT NULL,
	"deleted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "connections" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"at" timestamp with time zone NOT NULL,
	"proto" text NOT NULL,
	"local_ip" text NOT NULL,
	"local_port" integer NOT NULL,
	"remote_ip" text,
	"remote_port" integer,
	"state" text NOT NULL,
	"direction" text NOT NULL,
	"verdict" text NOT NULL,
	"reasons" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"intel_feed_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"pid" integer,
	"process_name" text,
	"exe" text,
	"country" text,
	"asn" integer,
	"org" text
);
--> statement-breakpoint
CREATE TABLE "destinations" (
	"agent_id" text NOT NULL,
	"remote_ip" text NOT NULL,
	"remote_port" integer NOT NULL,
	"direction" text NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"worst_verdict" text NOT NULL,
	"process_name" text,
	"country" text,
	"asn" integer,
	"org" text,
	"seen_count" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "destinations_agent_id_remote_ip_remote_port_direction_pk" PRIMARY KEY("agent_id","remote_ip","remote_port","direction")
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"agent_id" text NOT NULL,
	"finding_id" text NOT NULL,
	"scanner" text NOT NULL,
	"rule" text NOT NULL,
	"severity" text NOT NULL,
	"title" text NOT NULL,
	"detail" text NOT NULL,
	"evidence" jsonb NOT NULL,
	"recommendation" text DEFAULT '' NOT NULL,
	"actions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"intel_hits" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"allowlisted_by" text,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"resolved_at" timestamp with time zone,
	"acked_at" timestamp with time zone,
	"acked_by" text,
	"suppressed_until" timestamp with time zone,
	"suppress_reason" text,
	"content_hash" text NOT NULL,
	"first_report_id" text NOT NULL,
	"last_report_id" text NOT NULL,
	"indicator" text,
	CONSTRAINT "findings_agent_id_finding_id_pk" PRIMARY KEY("agent_id","finding_id")
);
--> statement-breakpoint
CREATE TABLE "intel_hits" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"finding_id" text NOT NULL,
	"report_id" text NOT NULL,
	"feed_id" text NOT NULL,
	"feed_name" text NOT NULL,
	"vendor" text NOT NULL,
	"license" text NOT NULL,
	"source_url" text NOT NULL,
	"confidence" integer NOT NULL,
	"indicator" text NOT NULL,
	"fetched_at" timestamp with time zone,
	"seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" text PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"schema_version" integer NOT NULL,
	"started_at" timestamp with time zone NOT NULL,
	"finished_at" timestamp with time zone NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	"scanners_run" jsonb NOT NULL,
	"score" jsonb NOT NULL,
	"findings_count" integer DEFAULT 0 NOT NULL,
	"new_count" integer DEFAULT 0 NOT NULL,
	"resolved_count" integer DEFAULT 0 NOT NULL,
	"partial" boolean DEFAULT false NOT NULL,
	"payload_bytes" integer DEFAULT 0 NOT NULL,
	"payload" jsonb,
	"source_ip" text
);
--> statement-breakpoint
ALTER TABLE "connections" ADD CONSTRAINT "connections_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "destinations" ADD CONSTRAINT "destinations_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "intel_hits" ADD CONSTRAINT "intel_hits_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "agents_last_seen_idx" ON "agents" USING btree ("last_seen_at");--> statement-breakpoint
CREATE INDEX "agents_hostname_idx" ON "agents" USING btree ("hostname");--> statement-breakpoint
CREATE INDEX "connections_agent_idx" ON "connections" USING btree ("agent_id");--> statement-breakpoint
CREATE INDEX "connections_verdict_idx" ON "connections" USING btree ("verdict");--> statement-breakpoint
CREATE INDEX "connections_remote_idx" ON "connections" USING btree ("remote_ip");--> statement-breakpoint
CREATE INDEX "destinations_remote_idx" ON "destinations" USING btree ("remote_ip");--> statement-breakpoint
CREATE INDEX "destinations_verdict_idx" ON "destinations" USING btree ("worst_verdict","last_seen_at");--> statement-breakpoint
CREATE INDEX "findings_status_sev_idx" ON "findings" USING btree ("status","severity");--> statement-breakpoint
CREATE INDEX "findings_agent_status_idx" ON "findings" USING btree ("agent_id","status");--> statement-breakpoint
CREATE INDEX "findings_scanner_idx" ON "findings" USING btree ("scanner");--> statement-breakpoint
CREATE INDEX "findings_indicator_idx" ON "findings" USING btree ("indicator");--> statement-breakpoint
CREATE INDEX "findings_last_seen_idx" ON "findings" USING btree ("last_seen_at");--> statement-breakpoint
CREATE INDEX "intel_hits_seen_idx" ON "intel_hits" USING btree ("seen_at");--> statement-breakpoint
CREATE INDEX "intel_hits_indicator_idx" ON "intel_hits" USING btree ("indicator");--> statement-breakpoint
CREATE INDEX "intel_hits_feed_seen_idx" ON "intel_hits" USING btree ("feed_id","seen_at");--> statement-breakpoint
CREATE INDEX "intel_hits_agent_finding_idx" ON "intel_hits" USING btree ("agent_id","finding_id");--> statement-breakpoint
CREATE INDEX "reports_agent_started_idx" ON "reports" USING btree ("agent_id","started_at");--> statement-breakpoint
CREATE INDEX "reports_received_idx" ON "reports" USING btree ("received_at");