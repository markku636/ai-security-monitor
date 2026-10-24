CREATE TABLE "web_findings" (
	"target_id" text NOT NULL,
	"finding_id" text NOT NULL,
	"scanner" text NOT NULL,
	"rule" text NOT NULL,
	"severity" text NOT NULL,
	"title" text NOT NULL,
	"detail" text DEFAULT '' NOT NULL,
	"recommendation" text DEFAULT '' NOT NULL,
	"location" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"evidence" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"cve" text,
	"cwe" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"cvss" double precision,
	"refs" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"first_seen_at" timestamp with time zone NOT NULL,
	"last_seen_at" timestamp with time zone NOT NULL,
	"resolved_at" timestamp with time zone,
	"acked_at" timestamp with time zone,
	"acked_by" text,
	"suppressed_until" timestamp with time zone,
	"suppress_reason" text,
	"content_hash" text NOT NULL,
	"first_job_id" text NOT NULL,
	"last_job_id" text NOT NULL,
	"fingerprint_ver" integer DEFAULT 1 NOT NULL,
	CONSTRAINT "web_findings_target_id_finding_id_pk" PRIMARY KEY("target_id","finding_id")
);
--> statement-breakpoint
CREATE TABLE "web_targets" (
	"id" text PRIMARY KEY NOT NULL,
	"url" text NOT NULL,
	"scheme" text NOT NULL,
	"host" text NOT NULL,
	"port" integer NOT NULL,
	"path" text DEFAULT '/' NOT NULL,
	"name" text DEFAULT '' NOT NULL,
	"verify_token" text NOT NULL,
	"verify_method" text,
	"verified_at" timestamp with time zone,
	"verify_checked_at" timestamp with time zone,
	"verify_error" text,
	"fingerprint" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"last_scan_at" timestamp with time zone,
	"last_job_id" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"created_by" text NOT NULL,
	"deleted_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "webscan_artifacts" (
	"id" bigserial PRIMARY KEY NOT NULL,
	"job_id" text NOT NULL,
	"scanner" text NOT NULL,
	"format" text NOT NULL,
	"exit_code" integer,
	"duration_ms" integer,
	"truncated" boolean DEFAULT false NOT NULL,
	"bytes" integer NOT NULL,
	"sha256" text NOT NULL,
	"content_gz" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "webscan_jobs" (
	"id" text PRIMARY KEY NOT NULL,
	"target_id" text NOT NULL,
	"kind" text NOT NULL,
	"profile" text NOT NULL,
	"scanners" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"spec" jsonb NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"runner_id" text,
	"attempts" integer DEFAULT 0 NOT NULL,
	"lease_expires_at" timestamp with time zone,
	"progress" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"result" jsonb,
	"error" text,
	"summary" jsonb,
	"requested_by" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"claimed_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "webscan_runners" (
	"id" text PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"version" text DEFAULT '' NOT NULL,
	"hostname" text DEFAULT '' NOT NULL,
	"source_ip" text,
	"capabilities" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"self_ips" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"first_seen_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "web_findings" ADD CONSTRAINT "web_findings_target_id_web_targets_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."web_targets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webscan_artifacts" ADD CONSTRAINT "webscan_artifacts_job_id_webscan_jobs_id_fk" FOREIGN KEY ("job_id") REFERENCES "public"."webscan_jobs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webscan_jobs" ADD CONSTRAINT "webscan_jobs_target_id_web_targets_id_fk" FOREIGN KEY ("target_id") REFERENCES "public"."web_targets"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "web_findings_status_sev_idx" ON "web_findings" USING btree ("status","severity");--> statement-breakpoint
CREATE INDEX "web_findings_scanner_idx" ON "web_findings" USING btree ("scanner");--> statement-breakpoint
CREATE INDEX "web_findings_cve_idx" ON "web_findings" USING btree ("cve");--> statement-breakpoint
CREATE UNIQUE INDEX "web_targets_url_uq" ON "web_targets" USING btree ("url") WHERE deleted_at is null;--> statement-breakpoint
CREATE INDEX "web_targets_host_idx" ON "web_targets" USING btree ("host");--> statement-breakpoint
CREATE INDEX "webscan_artifacts_job_idx" ON "webscan_artifacts" USING btree ("job_id");--> statement-breakpoint
CREATE INDEX "webscan_jobs_status_created_idx" ON "webscan_jobs" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "webscan_jobs_target_created_idx" ON "webscan_jobs" USING btree ("target_id","created_at");--> statement-breakpoint
CREATE UNIQUE INDEX "webscan_jobs_open_unique" ON "webscan_jobs" USING btree ("target_id","kind","profile") WHERE status in ('pending', 'running');