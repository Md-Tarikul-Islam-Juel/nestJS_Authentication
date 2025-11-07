-- Fix unique constraint on email to ignore soft-deleted rows
-- Following DATABASE_STANDARDS.md: "unique constraints that ignore soft-deleted rows"

-- Drop the existing unique index
DROP INDEX IF EXISTS "users_email_key";

-- Create a partial unique index that only applies to non-deleted rows
-- This allows the same email to exist multiple times if previous records are soft-deleted
CREATE UNIQUE INDEX "users_email_key" ON "users"("email") WHERE "deletedAt" IS NULL;

