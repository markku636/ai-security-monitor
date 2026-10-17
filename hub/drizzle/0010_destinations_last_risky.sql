ALTER TABLE "destinations" ADD COLUMN "last_risky_at" timestamp with time zone;--> statement-breakpoint
-- 既有的可疑／危險目的地沒有確切時間，先用最後看到的時間當作最後可疑時間
UPDATE "destinations" SET "last_risky_at" = "last_seen_at" WHERE "worst_verdict" IN ('dangerous', 'suspicious') AND "last_risky_at" IS NULL;
