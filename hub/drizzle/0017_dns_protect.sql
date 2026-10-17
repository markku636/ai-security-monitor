CREATE TABLE "dns_resolver_queries" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"server_id" text NOT NULL,
	"ts" timestamp with time zone NOT NULL,
	"client" text NOT NULL,
	"agent_id" text,
	"name" text NOT NULL,
	"registrable" text NOT NULL,
	"qtype" integer NOT NULL,
	"rcode" text NOT NULL,
	"blocked_by" text DEFAULT '' NOT NULL,
	"count" integer NOT NULL,
	"answers" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "dns_servers" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"agent_id" text,
	"version" text DEFAULT '' NOT NULL,
	"hostname" text DEFAULT '' NOT NULL,
	"source_ip" text,
	"status" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "dns_resolver_queries" ADD CONSTRAINT "dns_resolver_queries_server_id_dns_servers_id_fk" FOREIGN KEY ("server_id") REFERENCES "public"."dns_servers"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_resolver_queries" ADD CONSTRAINT "dns_resolver_queries_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dns_servers" ADD CONSTRAINT "dns_servers_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "dns_resolver_uq" ON "dns_resolver_queries" USING btree ("server_id","ts","client","name","qtype","rcode");--> statement-breakpoint
CREATE INDEX "dns_resolver_ts_idx" ON "dns_resolver_queries" USING btree ("ts");--> statement-breakpoint
CREATE INDEX "dns_resolver_reg_ts_idx" ON "dns_resolver_queries" USING btree ("registrable","ts");--> statement-breakpoint
CREATE INDEX "dns_resolver_client_ts_idx" ON "dns_resolver_queries" USING btree ("client","ts");--> statement-breakpoint
CREATE INDEX "dns_resolver_rcode_ts_idx" ON "dns_resolver_queries" USING btree ("rcode","ts");