CREATE TABLE "ip_domain_lookups" (
	"ip" text PRIMARY KEY NOT NULL,
	"results" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"queried_at" timestamp with time zone DEFAULT now() NOT NULL,
	"queried_by" text
);
--> statement-breakpoint
CREATE TABLE "ip_domains" (
	"agent_id" text NOT NULL,
	"ip" text NOT NULL,
	"domain" text NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	CONSTRAINT "ip_domains_agent_id_ip_domain_pk" PRIMARY KEY("agent_id","ip","domain")
);
--> statement-breakpoint
ALTER TABLE "ip_domains" ADD CONSTRAINT "ip_domains_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "ip_domain_lookups_queried_idx" ON "ip_domain_lookups" USING btree ("queried_at");--> statement-breakpoint
CREATE INDEX "ip_domains_ip_idx" ON "ip_domains" USING btree ("ip");--> statement-breakpoint
CREATE INDEX "ip_domains_seen_idx" ON "ip_domains" USING btree ("last_seen_at");