-- 002: Add Finance field and shared inventory snapshot storage.
-- Safe for both fresh databases and databases that already applied migration 001.
BEGIN;
ALTER TABLE branches
  ADD COLUMN IF NOT EXISTS monthly_revenue NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (monthly_revenue >= 0);
COMMIT;
