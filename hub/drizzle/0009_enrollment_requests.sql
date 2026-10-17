CREATE TABLE "enrollment_requests" (
	"id" text PRIMARY KEY NOT NULL,
	"agent_id" text NOT NULL,
	"hostname" text NOT NULL,
	"os_family" text,
	"os_name" text,
	"os_version" text,
	"arch" text,
	"agent_version" text,
	"ips" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"agent" jsonb,
	"accept_remote_actions" boolean DEFAULT false NOT NULL,
	"secret_hash" text NOT NULL,
	"request_code" text NOT NULL,
	"source_ip" text,
	"status" text DEFAULT 'pending' NOT NULL,
	"auto_approved" boolean DEFAULT false NOT NULL,
	"reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"decided_at" timestamp with time zone,
	"decided_by" text,
	"expires_at" timestamp with time zone NOT NULL,
	"claimed_at" timestamp with time zone,
	"enroll_key_id" text
);
--> statement-breakpoint
ALTER TABLE "enroll_keys" ADD COLUMN "bound_agent_id" text;--> statement-breakpoint
CREATE INDEX "enrollment_requests_status_idx" ON "enrollment_requests" USING btree ("status","created_at");--> statement-breakpoint
CREATE INDEX "enrollment_requests_agent_idx" ON "enrollment_requests" USING btree ("agent_id");