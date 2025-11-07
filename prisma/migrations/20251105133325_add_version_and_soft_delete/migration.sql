-- AlterTable
-- Add soft delete column (optimistic locking/version removed per requirements)
ALTER TABLE "users" ADD COLUMN "deletedAt" TIMESTAMP(3);
