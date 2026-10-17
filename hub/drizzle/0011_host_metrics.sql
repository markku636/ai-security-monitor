CREATE TABLE "host_metrics" (
	"agent_id" text NOT NULL,
	"at" timestamp with time zone NOT NULL,
	"interval_s" integer NOT NULL,
	"rx_bytes" bigint DEFAULT 0 NOT NULL,
	"tx_bytes" bigint DEFAULT 0 NOT NULL,
	"interfaces" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"processes" jsonb,
	"perf" boolean DEFAULT false NOT NULL,
	"cpu_pct" double precision,
	"cpu_cores" integer,
	"mem_used" bigint,
	"mem_total" bigint,
	"swap_used" bigint,
	"swap_total" bigint,
	"disks" jsonb,
	"disk_used_pct" double precision,
	"disk_read" bigint,
	"disk_write" bigint,
	"load1" double precision,
	"uptime_s" bigint,
	"top_cpu" jsonb,
	"top_mem" jsonb,
	"battery" jsonb,
	"received_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "host_metrics_agent_id_at_pk" PRIMARY KEY("agent_id","at")
);
--> statement-breakpoint
CREATE TABLE "host_metrics_hourly" (
	"agent_id" text NOT NULL,
	"hour" timestamp with time zone NOT NULL,
	"samples" integer DEFAULT 0 NOT NULL,
	"seconds" integer DEFAULT 0 NOT NULL,
	"rx_bytes" bigint DEFAULT 0 NOT NULL,
	"tx_bytes" bigint DEFAULT 0 NOT NULL,
	"interfaces" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"processes" jsonb,
	"perf_samples" integer DEFAULT 0 NOT NULL,
	"cpu_avg" double precision,
	"cpu_max" double precision,
	"mem_used_avg" bigint,
	"mem_used_max" bigint,
	"mem_total" bigint,
	"swap_used_max" bigint,
	"swap_total" bigint,
	"disk_used_pct_max" double precision,
	"disks" jsonb,
	"disk_read" bigint,
	"disk_write" bigint,
	"load1_avg" double precision,
	"battery_min" integer,
	"battery_last" integer,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "host_metrics_hourly_agent_id_hour_pk" PRIMARY KEY("agent_id","hour")
);
--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "metrics_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "perf_enabled" boolean;--> statement-breakpoint
ALTER TABLE "host_metrics" ADD CONSTRAINT "host_metrics_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "host_metrics_hourly" ADD CONSTRAINT "host_metrics_hourly_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "host_metrics_at_idx" ON "host_metrics" USING btree ("at");--> statement-breakpoint
CREATE INDEX "host_metrics_received_idx" ON "host_metrics" USING btree ("received_at");--> statement-breakpoint
CREATE INDEX "host_metrics_hourly_hour_idx" ON "host_metrics_hourly" USING btree ("hour");