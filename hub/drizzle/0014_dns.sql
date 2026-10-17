CREATE TABLE "dns_domains" (
	"registrable" text PRIMARY KEY NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"first_agent_id" text,
	"first_process" text
);
--> statement-breakpoint
CREATE TABLE "dns_queries" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"ts" timestamp with time zone NOT NULL,
	"name" text NOT NULL,
	"registrable" text NOT NULL,
	"qtype" integer NOT NULL,
	"rcode" text NOT NULL,
	"process" text DEFAULT '' NOT NULL,
	"exe" text,
	"count" integer NOT NULL,
	"answers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"cnames" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"source" text NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dns_queries_hourly" (
	"agent_id" text NOT NULL,
	"hour" timestamp with time zone NOT NULL,
	"registrable" text NOT NULL,
	"queries" integer DEFAULT 0 NOT NULL,
	"nxdomain" integer DEFAULT 0 NOT NULL,
	"names" integer DEFAULT 0 NOT NULL,
	"processes" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dns_queries_hourly_agent_id_hour_registrable_pk" PRIMARY KEY("agent_id","hour","registrable")
);
--> statement-breakpoint
ALTER TABLE "dns_queries" ADD CONSTRAINT "dns_queries_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_queries_hourly" ADD CONSTRAINT "dns_queries_hourly_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "dns_domains_first_idx" ON "dns_domains" USING btree ("first_seen_at");--> statement-breakpoint
CREATE INDEX "dns_domains_last_idx" ON "dns_domains" USING btree ("last_seen_at");--> statement-breakpoint
CREATE UNIQUE INDEX "dns_queries_uq" ON "dns_queries" USING btree ("agent_id","ts","name","qtype","rcode","process","source");--> statement-breakpoint
CREATE INDEX "dns_queries_agent_ts_idx" ON "dns_queries" USING btree ("agent_id","ts");--> statement-breakpoint
CREATE INDEX "dns_queries_reg_ts_idx" ON "dns_queries" USING btree ("registrable","ts");--> statement-breakpoint
CREATE INDEX "dns_queries_name_idx" ON "dns_queries" USING btree ("name");--> statement-breakpoint
CREATE INDEX "dns_queries_ts_idx" ON "dns_queries" USING btree ("ts");--> statement-breakpoint
CREATE INDEX "dns_queries_received_idx" ON "dns_queries" USING btree ("received_at");--> statement-breakpoint
CREATE INDEX "dns_hourly_reg_idx" ON "dns_queries_hourly" USING btree ("registrable","hour");--> statement-breakpoint
CREATE INDEX "dns_hourly_hour_idx" ON "dns_queries_hourly" USING btree ("hour");